// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "api_common.hpp"
#include "api_internal.h"
#include "api_service.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "bpf2c.h"
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_core.h"
#include "ebpf_tracelog.h"
#include "end_to_end_jit.h"
#include "helpers.h"
#include "ioctl_helper.h"
#include "mock.h"
namespace ebpf {
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"
}; // namespace ebpf
#include "cxplat_passed_test_log.h"
#include "platform.h"
#include "sample_test_common.h"
#include "test_helper.hpp"
#include "usersim/ke.h"
#include "watchdog.h"

#include <WinSock2.h>
#include <in6addr.h>
#include <array>
#include <cguid.h>
#include <chrono>
#include <lsalookup.h>
#include <mutex>
#define _NTDEF_ // UNICODE_STRING is already defined
#include <ntsecapi.h>
#include <thread>

using namespace Platform;

CATCH_REGISTER_LISTENER(cxplat_passed_test_log)
CATCH_REGISTER_LISTENER(_watchdog)

#define NATIVE_DRIVER_SERVICE_NAME L"test_service"
#define NATIVE_DRIVER_SERVICE_NAME_2 L"test_service2"
#define SERVICE_PATH_PREFIX L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
#define PARAMETERS_PATH_PREFIX L"System\\CurrentControlSet\\Services\\"
#define SERVICE_PARAMETERS L"Parameters"
#define NPI_MODULE_ID L"NpiModuleId"

#define BPF_PROG_TYPE_INVALID 100
#define BPF_ATTACH_TYPE_INVALID 100

#define DECLARE_ALL_TEST_CASES(_name, _group, _function) \
    DECLARE_JIT_TEST(_name, _group, _function)           \
    DECLARE_NATIVE_TEST(_name, _group, _function)        \
    DECLARE_INTERPRET_TEST(_name, _group, _function)

#define DECLARE_JIT_TEST_CASES(_name, _group, _function) \
    DECLARE_JIT_TEST(_name, _group, _function)           \
    DECLARE_NATIVE_TEST(_name, _group, _function)

void
append_udp_header(uint16_t udp_length, std::vector<uint8_t>& ip_packet)
{
    ip_packet.resize(ip_packet.size() + sizeof(ebpf::UDP_HEADER));
    auto ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(ip_packet.data());
    ebpf::UDP_HEADER* udp;
    if (ethernet_header->Type == ntohs(ETHERNET_TYPE_IPV4)) {
        auto ipv4_header = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);
        ipv4_header->Protocol = IPPROTO_UDP;
        udp = reinterpret_cast<ebpf::UDP_HEADER*>(ipv4_header + 1);
    } else {
        auto ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(ethernet_header + 1);
        ipv6->NextHeader = IPPROTO_UDP;
        udp = reinterpret_cast<ebpf::UDP_HEADER*>(ipv6 + 1);
    }
    udp->length = udp_length;
}

std::vector<uint8_t>
prepare_udp_packet(uint16_t udp_length, uint16_t ethernet_type)
{
    auto packet = prepare_ip_packet(ethernet_type);
    append_udp_header(udp_length, packet);
    return packet;
}

typedef class _udp_packet : public ip_packet_t
{
  public:
    _udp_packet(
        ADDRESS_FAMILY address_family,
        _In_ const std::array<uint8_t, 6>& source_mac = _test_source_mac,
        _In_ const std::array<uint8_t, 6>& destination_mac = _test_destination_mac,
        _In_opt_ const void* ip_addresses = nullptr,
        uint16_t datagram_length = 1024)
        : ip_packet_t{address_family, source_mac, destination_mac, ip_addresses}
    {
        append_udp_header(sizeof(ebpf::UDP_HEADER) + datagram_length, _packet);
    }

    static const ebpf::UDP_HEADER*
    _get_udp_header(_In_ const uint8_t* packet_buffer, ADDRESS_FAMILY address_family)
    {
        auto ethernet_header = reinterpret_cast<const ebpf::ETHERNET_HEADER*>(packet_buffer);
        const ebpf::UDP_HEADER* udp = nullptr;
        if (address_family == AF_INET) {
            auto ip = reinterpret_cast<const ebpf::IPV4_HEADER*>(ethernet_header + 1);
            udp = reinterpret_cast<const ebpf::UDP_HEADER*>(ip + 1);
        } else {
            REQUIRE(address_family == AF_INET6);
            auto ip = reinterpret_cast<const ebpf::IPV6_HEADER*>(ethernet_header + 1);
            udp = reinterpret_cast<const ebpf::UDP_HEADER*>(ip + 1);
        }
        return udp;
    }

    void
    set_source_port(uint16_t source_port)
    {
        auto udp = const_cast<ebpf::UDP_HEADER*>(_get_udp_header(_packet.data(), _address_family));
        udp->srcPort = source_port;
    }

    void
    set_destination_port(uint16_t destination_port)
    {
        auto udp = const_cast<ebpf::UDP_HEADER*>(_get_udp_header(_packet.data(), _address_family));
        udp->destPort = destination_port;
    }

} udp_packet_t;

#define TEST_IFINDEX 17

static ebpf_result_t
ebpf_authorize_native_module_wrapper(_In_ const GUID* module_id, _In_z_ const char* filename)
{
    HANDLE file_handle = INVALID_HANDLE_VALUE;
    ebpf_result_t result = ebpf_verify_signature_and_open_file(filename, &file_handle);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    result = ebpf_authorize_native_module(module_id, file_handle);
    CloseHandle(file_handle);
    return result;
}

// See also divide_by_zero_test_km in api_test.cpp for the kernel-mode equivalent.
void
divide_by_zero_test_um(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "divide_by_zero_um.dll" : "divide_by_zero.o");
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);
    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);

    // Empty context (not used by the eBPF program).
    INITIALIZE_SAMPLE_CONTEXT;

    uint32_t hook_result = 0;
    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 0);

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

void
bad_map_name_um(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "bad_map_name_um.dll" : "bad_map_name.o");

    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == -EINVAL);

    bpf_object__close(unique_object.release());
}

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

typedef struct _audit_entry
{
    uint64_t logon_id;
    int32_t is_admin;
} audit_entry_t;

uint32_t
get_bind_count_for_pid(fd_t map_fd, uint64_t pid)
{
    process_entry_t entry{};
    bpf_map_lookup_elem(map_fd, &pid, &entry);

    return entry.count;
}

static void
_validate_bind_audit_entry(fd_t map_fd, uint64_t pid)
{
    audit_entry_t entry = {0};
    int result = bpf_map_lookup_elem(map_fd, &pid, &entry);
    REQUIRE(result == 0);

    REQUIRE(entry.is_admin == -1);

    REQUIRE(entry.logon_id != 0);
    SECURITY_LOGON_SESSION_DATA* data = NULL;
    result = LsaGetLogonSessionData((PLUID)&entry.logon_id, &data);
    REQUIRE(result == ERROR_SUCCESS);

    LsaFreeReturnBuffer(data);
}

bind_action_t
emulate_bind(std::function<ebpf_result_t(void*, uint32_t*)>& invoke, uint64_t pid, const char* appid)
{
    uint32_t result;
    std::string app_id = appid;
    INITIALIZE_BIND_CONTEXT

    ctx->app_id_start = (uint8_t*)app_id.c_str();
    ctx->app_id_end = (uint8_t*)(app_id.c_str()) + app_id.size();
    ctx->process_id = pid;
    ctx->operation = BIND_OPERATION_BIND;
    REQUIRE(invoke(reinterpret_cast<void*>(ctx), &result) == EBPF_SUCCESS);
    return static_cast<bind_action_t>(result);
}

void
emulate_unbind(std::function<ebpf_result_t(void*, uint32_t*)>& invoke, uint64_t pid, const char* appid)
{
    uint32_t result;
    std::string app_id = appid;
    INITIALIZE_BIND_CONTEXT

    ctx->process_id = pid;
    ctx->operation = BIND_OPERATION_UNBIND;
    REQUIRE(invoke(ctx, &result) == EBPF_SUCCESS);
}

void
set_bind_limit(fd_t map_fd, uint32_t limit)
{
    uint32_t limit_key = 0;
    REQUIRE(bpf_map_update_elem(map_fd, &limit_key, &limit, EBPF_ANY) == EBPF_SUCCESS);
}

static uint64_t
_get_current_pid_tgid()
{
    return ((uint64_t)GetCurrentProcessId() << 32 | GetCurrentThreadId());
}

void
bindmonitor_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    uint64_t fake_pid = 12345;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;
    uint64_t process_id = _get_current_pid_tgid();

    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    // Note: We are deliberately using "bindmonitor_um.dll" here as we want the programs to be loaded from
    // the individual dll, instead of the combined DLL. This helps in testing the DLL stub which is generated
    // bpf2c.exe tool.
    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_um.dll" : "bindmonitor.o");

    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);
    fd_t limit_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "limits_map");
    REQUIRE(limit_map_fd > 0);
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "process_map");
    REQUIRE(process_map_fd > 0);
    fd_t audit_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "audit_map");
    REQUIRE(audit_map_fd > 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Apply policy of maximum 2 binds per process
    set_bind_limit(limit_map_fd, 2);

    std::function<ebpf_result_t(void*, uint32_t*)> invoke =
        [&hook](_Inout_ void* context, _Out_ uint32_t* result) -> ebpf_result_t { return hook.fire(context, result); };
    // Bind first port - success
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    // Bind second port - success
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    // Bind third port - blocked
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_DENY);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    // Unbind second port
    emulate_unbind(invoke, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    // Unbind first port
    emulate_unbind(invoke, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 0);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    // Bind from two apps to test enumeration
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    fake_pid = 54321;
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_2") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    uint64_t pid;
    REQUIRE(bpf_map_get_next_key(process_map_fd, NULL, &pid) == 0);
    REQUIRE(pid != 0);
    REQUIRE(bpf_map_get_next_key(process_map_fd, &pid, &pid) == 0);
    REQUIRE(pid != 0);
    REQUIRE(bpf_map_get_next_key(process_map_fd, &pid, &pid) < 0);
    REQUIRE(errno == ENOENT);

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

static void
_bindmonitor_bpf2bpf_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);

    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_bpf2bpf_um.dll" : "bindmonitor_bpf2bpf.o");
    program_load_attach_helper_t program_helper;
    program_helper.initialize(file_name, BPF_PROG_TYPE_BIND, "BindMonitor_Caller", execution_type, nullptr, 0, hook);

    std::function<ebpf_result_t(void*, uint32_t*)> invoke =
        [&hook](_Inout_ void* context, _Out_ uint32_t* result) -> ebpf_result_t { return hook.fire(context, result); };

    REQUIRE(emulate_bind(invoke, 0, "fake_app_0") == BIND_DENY);
    REQUIRE(emulate_bind(invoke, 1, "fake_app_1") == BIND_REDIRECT);
    REQUIRE(emulate_bind(invoke, 2, "fake_app_2") == BIND_PERMIT);
}

void
bindmonitor_tailcall_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    uint64_t fake_pid = 12345;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;

    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_tailcall_um.dll" : "bindmonitor_tailcall.o");
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);
    fd_t limit_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "limits_map");
    REQUIRE(limit_map_fd > 0);
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "process_map");
    REQUIRE(process_map_fd > 0);

    // Set up tail calls.
    struct bpf_program* callee0 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "prog_array_map");
    REQUIRE(prog_map_fd > 0);

    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    // Validate various maps.

    // Validate map-in-maps with "inner_id".
    struct bpf_map* outer_map = bpf_object__find_map_by_name(unique_object.get(), "dummy_outer_map");
    REQUIRE(outer_map != nullptr);

    int outer_map_fd = bpf_map__fd(outer_map);
    REQUIRE(outer_map_fd > 0);

    // Validate map-in-maps with "inner_idx".
    struct bpf_map* outer_idx_map = bpf_object__find_map_by_name(unique_object.get(), "dummy_outer_idx_map");
    REQUIRE(outer_idx_map != nullptr);

    int outer_idx_map_fd = bpf_map__fd(outer_idx_map);
    REQUIRE(outer_idx_map_fd > 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Apply policy of maximum 2 binds per process
    set_bind_limit(limit_map_fd, 2);

    std::function<ebpf_result_t(void*, uint32_t*)> invoke =
        [&hook](_Inout_ void* context, _Out_ uint32_t* result) -> ebpf_result_t { return hook.fire(context, result); };
    // Bind first port - success
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    // Bind second port - success
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);

    // Bind third port - blocked
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_DENY);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);

    // Unbind second port
    emulate_unbind(invoke, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    // Unbind first port
    emulate_unbind(invoke, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 0);

    // Bind from two apps to test enumeration
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    fake_pid = 54321;
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_2") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    uint64_t pid;
    REQUIRE(bpf_map_get_next_key(process_map_fd, NULL, &pid) == 0);
    REQUIRE(pid != 0);
    REQUIRE(bpf_map_get_next_key(process_map_fd, &pid, &pid) == 0);
    REQUIRE(pid != 0);
    REQUIRE(bpf_map_get_next_key(process_map_fd, &pid, &pid) < 0);
    REQUIRE(errno == ENOENT);

    hook.detach_and_close_link(&link);

    index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

    bpf_object__close(unique_object.release());
}

void
negative_ring_buffer_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "bpf_call_um.dll" : "bpf_call.o");

    // Load eBPF program.
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    fd_t map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "map");
    REQUIRE(map_fd > 0);

    // Calls to ring buffer APIs on this map (array_map) must fail.
    ebpf_ring_buffer_opts ring_opts{.sz = sizeof(ring_opts), .flags = EBPF_RINGBUF_FLAG_AUTO_CALLBACK};
    REQUIRE(ebpf_ring_buffer__new(map_fd, [](void*, void*, size_t) { return 0; }, nullptr, &ring_opts) == nullptr);
    REQUIRE(libbpf_get_error(nullptr) == EINVAL);
    uint8_t data = 0;
    REQUIRE(ebpf_ring_buffer_map_write(map_fd, &data, sizeof(data)) == EBPF_INVALID_ARGUMENT);

    bpf_object__close(unique_object.release());
}

void
bindmonitor_ring_buffer_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;

    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_ringbuf_um.dll" : "bindmonitor_ringbuf.o");

    // Load and attach a bind eBPF program that uses a ring buffer map to notify about bind operations.
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    fd_t process_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "process_map");
    REQUIRE(process_map_fd > 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);

    // Create a list of fake app IDs and set it to event context.
    std::string fake_app_ids_prefix = "fake_app";
    std::vector<std::vector<char>> fake_app_ids;
    for (int i = 0; i < RING_BUFFER_TEST_EVENT_COUNT; i++) {
        std::string temp = fake_app_ids_prefix + std::to_string(i);
        std::vector<char> fake_app_id(temp.begin(), temp.end());
        fake_app_ids.push_back(fake_app_id);
    }

    uint64_t fake_pid = 12345;
    std::function<ebpf_result_t(void*, uint32_t*)> invoke =
        [&hook](_Inout_ void* context, _Out_ uint32_t* result) -> ebpf_result_t { return hook.fire(context, result); };

    // Test multiple subscriptions to the same ring buffer map, to ensure that the ring buffer map will continue
    // to provide notifications to the subscriber.
    for (int i = 0; i < 3; i++) {

        ring_buffer_api_test_helper(process_map_fd, fake_app_ids, [&](int i) {
            // Emulate bind operation.
            std::vector<char> fake_app_id = fake_app_ids[i];
            fake_app_id.push_back('\0');
            REQUIRE(emulate_bind(invoke, fake_pid + i, fake_app_id.data()) == BIND_PERMIT);
        });
    }

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

static void
_utility_helper_functions_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "test_utility_helpers_um.dll" : "test_utility_helpers.o");
    program_load_attach_helper_t program_helper;
    program_helper.initialize(
        file_name, BPF_PROG_TYPE_SAMPLE, "test_utility_helpers", execution_type, nullptr, 0, hook);
    bpf_object* object = program_helper.get_object();

    // Dummy context (not used by the eBPF program).
    INITIALIZE_SAMPLE_CONTEXT

    uint32_t hook_result = 0;
    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 0);

    verify_utility_helper_results(object, true);
}

void
map_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_um.dll" : "map.o");

    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_SAMPLE, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);
    uint32_t hook_result = 0;
    INITIALIZE_SAMPLE_CONTEXT
    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    // Program should return 0 if all the map tests pass.
    REQUIRE(hook_result >= 0);

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

void
global_variable_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;

    if (execution_type != EBPF_EXECUTION_NATIVE) {
        // Skip this test in JIT-compiled and interpreted mode.
        return;
    }

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "global_vars_um.dll" : "global_vars.o");

    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_SAMPLE, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    auto rodata = bpf_object__find_map_by_name(unique_object.get(), "global_.rodata");
    REQUIRE(rodata != nullptr);
    auto rodata_fd = bpf_map__fd(rodata);
    REQUIRE(rodata_fd > 0);

    auto data = bpf_object__find_map_by_name(unique_object.get(), "global_.data");
    REQUIRE(data != nullptr);
    auto data_fd = bpf_map__fd(data);
    REQUIRE(data_fd > 0);

    auto bss = bpf_object__find_map_by_name(unique_object.get(), "global_.bss");
    REQUIRE(bss != nullptr);
    auto bss_fd = bpf_map__fd(bss);
    REQUIRE(bss_fd > 0);

    uint32_t key = 0;
    uint32_t value[2] = {};
    REQUIRE(bpf_map_lookup_elem(bss_fd, &key, value) == EBPF_SUCCESS);
    REQUIRE(value[0] == 0);

    REQUIRE(bpf_map_lookup_elem(rodata_fd, &key, value) == EBPF_SUCCESS);
    REQUIRE(value[0] == 10);

    REQUIRE(bpf_map_lookup_elem(data_fd, &key, value) == EBPF_SUCCESS);
    REQUIRE(value[0] == 20);
    REQUIRE(value[1] == 40);

    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);
    uint32_t hook_result = 0;
    INITIALIZE_SAMPLE_CONTEXT
    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    // Program should return 0 if all the map tests pass.
    REQUIRE(hook_result >= 0);

    value[0] = 0;
    REQUIRE(bpf_map_lookup_elem(bss_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value[0] == 70);

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

void
global_variable_and_map_test(ebpf_execution_type_t execution_type)
{
    typedef struct _some_config_struct
    {
        int some_config_field;
        int some_other_config_field;
        uint64_t some_config_field_64;
        uint64_t some_other_config_field_64;
    } some_config_struct_t;

    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;

    if (execution_type != EBPF_EXECUTION_NATIVE) {
        // Skip this test in JIT-compiled and interpreted mode.
        return;
    }

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "global_vars_and_map_um.dll" : "global_vars_and_map.o");

    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_SAMPLE, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    auto bss = bpf_object__find_map_by_name(unique_object.get(), "global_.bss");
    REQUIRE(bss != nullptr);
    auto bss_fd = bpf_map__fd(bss);
    REQUIRE(bss_fd > 0);

    auto some_config_map = bpf_object__find_map_by_name(unique_object.get(), "some_config_map");
    REQUIRE(some_config_map != nullptr);
    auto some_config_map_fd = bpf_map__fd(some_config_map);
    REQUIRE(some_config_map_fd > 0);

    uint32_t key = 0;
    some_config_struct_t value{};
    REQUIRE(bpf_map_lookup_elem(bss_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value.some_config_field == 0);
    REQUIRE(value.some_other_config_field == 0);
    REQUIRE(value.some_config_field_64 == 0);
    REQUIRE(value.some_other_config_field_64 == 0);

    value.some_config_field = 10;
    value.some_other_config_field = 20;
    value.some_config_field_64 = 30;
    value.some_other_config_field_64 = 40;

    REQUIRE(bpf_map_update_elem(some_config_map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);

    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);
    uint32_t hook_result = 0;
    INITIALIZE_SAMPLE_CONTEXT
    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    // Program should return 0 if all the map tests pass.
    REQUIRE(hook_result >= 0);

    value = {};
    REQUIRE(bpf_map_lookup_elem(bss_fd, &key, &value) == EBPF_SUCCESS);

    REQUIRE(value.some_config_field == 10);
    REQUIRE(value.some_other_config_field == 20);
    REQUIRE(value.some_config_field_64 == 30);
    REQUIRE(value.some_other_config_field_64 == 40);

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

DECLARE_ALL_TEST_CASES("divide_by_zero", "[end_to_end]", divide_by_zero_test_um);
DECLARE_ALL_TEST_CASES("bindmonitor", "[end_to_end]", bindmonitor_test);
DECLARE_ALL_TEST_CASES("bindmonitor-bpf2bpf", "[end_to_end]", _bindmonitor_bpf2bpf_test);
DECLARE_ALL_TEST_CASES("bindmonitor-tailcall", "[end_to_end]", bindmonitor_tailcall_test);
DECLARE_ALL_TEST_CASES("bindmonitor-ringbuf", "[end_to_end]", bindmonitor_ring_buffer_test);
DECLARE_ALL_TEST_CASES("negative_ring_buffer_test", "[end_to_end]", negative_ring_buffer_test);
DECLARE_ALL_TEST_CASES("utility-helpers", "[end_to_end]", _utility_helper_functions_test);
DECLARE_ALL_TEST_CASES("map", "[end_to_end]", map_test);
DECLARE_ALL_TEST_CASES("bad_map_name", "[end_to_end]", bad_map_name_um);
DECLARE_ALL_TEST_CASES("global_variable", "[end_to_end]", global_variable_test);
DECLARE_ALL_TEST_CASES("global_variable_and_map", "[end_to_end]", global_variable_and_map_test);

TEST_CASE("enum programs", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    ebpf_api_program_info_t* program_data = nullptr;
    uint32_t result;

    REQUIRE(
        (result = ebpf_enumerate_programs(SAMPLE_PATH "test_sample_ebpf.o", true, &program_data, &error_message),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    for (auto current_program = program_data; current_program != nullptr; current_program = current_program->next) {
        ebpf_stat_t* stat = current_program->stats;
        REQUIRE(strcmp(stat->key, "Instructions") == 0);
        REQUIRE(stat->value == 40);
    }
    ebpf_free_programs(program_data);
    ebpf_free_string(error_message);
}

TEST_CASE("verify program", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;
    program_info_provider_t sample_test_program_info;
    REQUIRE(sample_test_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    ebpf_api_verifier_stats_t stats;
    REQUIRE(
        (result = ebpf_api_elf_verify_program_from_file(
             SAMPLE_PATH "test_sample_ebpf.o",
             "sample_ext",
             "test_program_entry",
             nullptr,
             EBPF_VERIFICATION_VERBOSITY_NORMAL,
             &report,
             &error_message,
             &stats),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    REQUIRE(report != nullptr);
    ebpf_free_string(report);
}

TEST_CASE("verify program with invalid program type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;
    program_info_provider_t sample_test_program_info;
    REQUIRE(sample_test_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    ebpf_api_verifier_stats_t stats;
    result = ebpf_api_elf_verify_program_from_file(
        SAMPLE_PATH "test_sample_ebpf.o",
        "sample_ext",
        "test_program_entry",
        &EBPF_PROGRAM_TYPE_UNSPECIFIED,
        EBPF_VERIFICATION_VERBOSITY_NORMAL,
        &report,
        &error_message,
        &stats);

    REQUIRE(result == 1);
    REQUIRE(error_message != nullptr);
    ebpf_free_string(error_message);
}

#define DECLARE_CGROUP_SOCK_ADDR_LOAD_NATIVE_TEST(file, name, attach_type) \
    DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST2(file, name, attach_type, "native", "_um.dll", EBPF_EXECUTION_NATIVE)

#define DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST(file, name, attach_type) \
    DECLARE_CGROUP_SOCK_ADDR_LOAD_JIT_TEST(file, name, attach_type) \
    DECLARE_CGROUP_SOCK_ADDR_LOAD_NATIVE_TEST(file, name, attach_type)

DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST(
    SAMPLE_PATH "cgroup_sock_addr", "authorize_connect4", EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT);
DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST(
    SAMPLE_PATH "cgroup_sock_addr", "authorize_connect6", EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT);
DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST(
    SAMPLE_PATH "cgroup_sock_addr", "authorize_recv_accept4", EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT);
DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST(
    SAMPLE_PATH "cgroup_sock_addr", "authorize_recv_accept6", EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT);

TEST_CASE("verify_test0", "[sample_extension]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t sample_extension_program_info;
    REQUIRE(sample_extension_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;

    ebpf_api_verifier_stats_t stats;
    REQUIRE(
        (result = ebpf_api_elf_verify_program_from_file(
             SAMPLE_PATH "test_sample_ebpf.o",
             "sample_ext",
             "test_program_entry",
             nullptr,
             EBPF_VERIFICATION_VERBOSITY_NORMAL,
             &report,
             &error_message,
             &stats),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    REQUIRE(report != nullptr);
    ebpf_free_string(report);
}

TEST_CASE("verify_test1", "[sample_extension]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    program_info_provider_t sample_extension_program_info;
    REQUIRE(sample_extension_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;

    ebpf_api_verifier_stats_t stats;

    REQUIRE(
        (result = ebpf_api_elf_verify_program_from_file(
             SAMPLE_PATH "test_sample_ebpf.o",
             "sample_ext",
             nullptr,
             nullptr,
             EBPF_VERIFICATION_VERBOSITY_NORMAL,
             &report,
             &error_message,
             &stats),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    REQUIRE(report != nullptr);
    ebpf_free_string(report);

    REQUIRE(result == 0);
}

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("map_pinning_test", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    result = ebpf_program_load(
        SAMPLE_PATH "bindmonitor.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_INTERPRET,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);

    std::string process_maps_name = "bindmonitor/process_map";
    std::string limit_maps_name = "bindmonitor/limits_map";

    REQUIRE(bpf_object__find_map_by_name(unique_object.get(), "process_map") != nullptr);
    REQUIRE(bpf_object__find_map_by_name(unique_object.get(), "limits_map") != nullptr);
    REQUIRE(
        bpf_map__pin(bpf_object__find_map_by_name(unique_object.get(), "process_map"), process_maps_name.c_str()) ==
        EBPF_SUCCESS);
    REQUIRE(
        bpf_map__pin(bpf_object__find_map_by_name(unique_object.get(), "limits_map"), limit_maps_name.c_str()) ==
        EBPF_SUCCESS);

    fd_t fd = bpf_obj_get(process_maps_name.c_str());
    REQUIRE(fd != ebpf_fd_invalid);
    Platform::_close(fd);

    fd = bpf_obj_get(limit_maps_name.c_str());
    REQUIRE(fd != ebpf_fd_invalid);
    Platform::_close(fd);

    REQUIRE(
        bpf_map__unpin(bpf_object__find_map_by_name(unique_object.get(), "process_map"), process_maps_name.c_str()) ==
        EBPF_SUCCESS);
    REQUIRE(
        bpf_map__unpin(bpf_object__find_map_by_name(unique_object.get(), "limits_map"), limit_maps_name.c_str()) ==
        EBPF_SUCCESS);

    REQUIRE(bpf_obj_get(limit_maps_name.c_str()) == -ENOENT);

    REQUIRE(bpf_obj_get(process_maps_name.c_str()) == -ENOENT);

    bpf_object__close(unique_object.release());
}
#endif

TEST_CASE("pinned_map_enum", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // Test with verifying literal pin path value.
    ebpf_test_pinned_map_enum(true);
}

TEST_CASE("pinned_map_enum2", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // Test without verifying literal pin path value.
    // This test can be used in regression tests even if
    // the pin path syntax changes.
    ebpf_test_pinned_map_enum(false);
}

static void
_verify_canonical_path(int fd, _In_z_ const char* original_path, _In_z_ const char* canonical_path)
{
    char path[EBPF_MAX_PIN_PATH_LENGTH] = "";
    REQUIRE(ebpf_canonicalize_pin_path(path, sizeof(path), original_path) == EBPF_SUCCESS);
    REQUIRE(strcmp(path, canonical_path) == 0);

    // Pin the fd to the original path.
    REQUIRE(ebpf_object_pin(fd, original_path) == EBPF_SUCCESS);

    // Look up id for the fd.
    bpf_map_info info = {};
    uint32_t info_size = sizeof(info);
    int result = bpf_obj_get_info_by_fd(fd, &info, &info_size);
    REQUIRE(result == 0);
    ebpf_id_t id = info.id;

    REQUIRE(info.pinned_path_count == 1);

    // Look up the actual path pinned.
    ebpf_object_type_t object_type = EBPF_OBJECT_UNKNOWN;
    while (ebpf_get_next_pinned_object_path(path, path, sizeof(path), &object_type) == EBPF_SUCCESS) {
        int fd2 = bpf_obj_get(path);
        if (fd2 < 0) {
            continue;
        }
        if ((bpf_obj_get_info_by_fd(fd2, &info, &info_size) == 0) && (info.id == id)) {
            // Verify the path is what we expect.
            REQUIRE(strcmp(path, canonical_path) == 0);
        }
        Platform::_close(fd2);
    }

    // Verify we can unpin it by the original path.
    REQUIRE(ebpf_object_unpin(original_path) == EBPF_SUCCESS);
}

TEST_CASE("pin path canonicalization", "[end_to_end][pinning]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    fd_t map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "test_map", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(map_fd > 0);

    // Verify pin path canonicalization.
    _verify_canonical_path(map_fd, "BPF:\\.\\my\\pin\\path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "BPF:/./my/pin/path", "BPF:\\my\\pin\\path");

    // Try Linux-style absolute paths.
    _verify_canonical_path(map_fd, "/sys/fs/bpf/my/pin/path", "BPF:\\sys\\fs\\bpf\\my\\pin\\path");
    _verify_canonical_path(map_fd, "/sys/fs/bpf/My/Pin/Path", "BPF:\\sys\\fs\\bpf\\My\\Pin\\Path");

    // Try Linux-style relative paths.
    _verify_canonical_path(map_fd, "my/pin/path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "my/pin/./path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "my/pin//path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "my/pin/./././path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "my/pin/oops/../path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "my/pin/oops/again/../../path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "My/Pin/Path", "BPF:\\My\\Pin\\Path");

    // Try Windows-style relative paths.
    _verify_canonical_path(map_fd, "my\\pin\\path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "my\\pin\\.\\path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "my\\pin\\oops\\..\\path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "my\\pin\\path\\oops\\..", "BPF:\\my\\pin\\path");

    // Try a Windows-style absolute path without the device.
    _verify_canonical_path(map_fd, "\\my\\pin\\path", "BPF:\\my\\pin\\path");
    _verify_canonical_path(map_fd, "\\sys\\fs\\bpf\\my\\pin\\path", "BPF:\\sys\\fs\\bpf\\my\\pin\\path");

    // Try a legacy eBPF-for-Windows path.
    _verify_canonical_path(map_fd, "/ebpf/global/my/pin/path", "BPF:\\my\\pin\\path");

    // Try a mix of slash and backslash.
    _verify_canonical_path(map_fd, "my\\pin/path", "BPF:\\my\\pin\\path");

    // Verify invalid paths fail.
    REQUIRE(ebpf_object_pin(map_fd, "..") == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_object_pin(map_fd, "/..") == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_object_pin(map_fd, "/mypinpath/../..") == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_object_pin(map_fd, "C:\\") == EBPF_INVALID_ARGUMENT);

    Platform::_close(map_fd);
}

TEST_CASE("ebpf_get_next_pinned_object_path", "[end_to_end][pinning]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    bpf_object_ptr unique_object;
    fd_t program_fd;
    const char* error_message = nullptr;

    int result = ebpf_program_load(
        SAMPLE_PATH "test_sample_ebpf_um.dll",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_NATIVE,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);
    REQUIRE(program_fd > 0);

    fd_t map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "test_map", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(map_fd > 0);

    // Pin the program and map multiple times with a shared prefix.
    // We use canonical paths here so we can verify that what is
    // enumerated is identical to the paths we pinned.
    const char* prefix = "BPF:\\";
    const char* paths[] = {
        "BPF:\\map1",
        "BPF:\\map2",
        "BPF:\\program1",
        "BPF:\\program2",
    };
    const ebpf_object_type_t object_types[] = {
        EBPF_OBJECT_MAP,
        EBPF_OBJECT_MAP,
        EBPF_OBJECT_PROGRAM,
        EBPF_OBJECT_PROGRAM,
    };

    REQUIRE(bpf_obj_pin(map_fd, paths[0]) == 0);
    REQUIRE(bpf_obj_pin(map_fd, paths[1]) == 0);
    REQUIRE(bpf_obj_pin(program_fd, paths[2]) == 0);
    REQUIRE(bpf_obj_pin(program_fd, paths[3]) == 0);

    char path[EBPF_MAX_PIN_PATH_LENGTH];
    size_t expected_count = sizeof(paths) / sizeof(paths[0]);
    const char* start_path = prefix;
    size_t count = 0;

    // Enumerate all pinned objects.
    ebpf_object_type_t object_type = EBPF_OBJECT_UNKNOWN;
    while (ebpf_get_next_pinned_object_path(start_path, path, sizeof(path), &object_type) == EBPF_SUCCESS) {
        if (strncmp(path, prefix, strlen(prefix)) != 0) {
            break;
        }

        REQUIRE(object_type == object_types[count]);
        REQUIRE(count < expected_count);
        REQUIRE(strcmp(path, paths[count]) == 0);

        count++;
        start_path = path;
        object_type = EBPF_OBJECT_UNKNOWN;
    }

    REQUIRE(count == expected_count);

    // Only iterate over programs.
    start_path = prefix;
    count = 2;
    object_type = EBPF_OBJECT_PROGRAM;
    while (ebpf_get_next_pinned_object_path(start_path, path, sizeof(path), &object_type) == EBPF_SUCCESS) {
        if (strncmp(path, prefix, strlen(prefix)) != 0) {
            break;
        }

        REQUIRE(object_type == EBPF_OBJECT_PROGRAM);
        REQUIRE(count < expected_count);
        REQUIRE(strcmp(path, paths[count]) == 0);

        count++;
        start_path = path;
    }

    REQUIRE(count == expected_count);

    // Try some non-canonical paths.
    object_type = EBPF_OBJECT_UNKNOWN;
    REQUIRE(ebpf_get_next_pinned_object_path("/", path, sizeof(path), &object_type) == EBPF_SUCCESS);
    REQUIRE(strcmp(path, "BPF:\\map1") == 0);
    object_type = EBPF_OBJECT_UNKNOWN;
    REQUIRE(ebpf_get_next_pinned_object_path("/none", path, sizeof(path), &object_type) == EBPF_SUCCESS);
    REQUIRE(strcmp(path, "BPF:\\program1") == 0);
    object_type = EBPF_OBJECT_UNKNOWN;
    REQUIRE(ebpf_get_next_pinned_object_path("/foo/../ebpf", path, sizeof(path), &object_type) == EBPF_SUCCESS);
    REQUIRE(strcmp(path, "BPF:\\map1") == 0);
    object_type = EBPF_OBJECT_UNKNOWN;
    REQUIRE(ebpf_get_next_pinned_object_path("/foo/../zub", path, sizeof(path), &object_type) == EBPF_NO_MORE_KEYS);

    // Clean up.
    REQUIRE(ebpf_object_unpin(paths[0]) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin(paths[1]) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin(paths[2]) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin(paths[3]) == EBPF_SUCCESS);
    Platform::_close(map_fd);
    bpf_object__close(unique_object.release());
}

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("explicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Call detach API and then close the link handle. The link object
    //    should be deleted.
    // 2. Close program handle. The program object should be deleted.

    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;
    int result;
    const char* error_message = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    result = ebpf_program_load(
        SAMPLE_PATH "test_sample_ebpf.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_INTERPRET,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);

    // Detach and close link handle.
    // ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.detach_and_close_link(&link);

    // Program should still be loaded.
    uint32_t program_id;
    REQUIRE(bpf_prog_get_next_id(0, &program_id) == 0);

    // Close program handle.
    bpf_object__close(unique_object.release());
    REQUIRE(bpf_prog_get_next_id(0, &program_id) == -ENOENT);
}

TEST_CASE("implicit_explicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Close the program handle so that an implicit detach happens.
    // 2. Explicitly call detach and then close the link handle. Explicit
    //    detach in this step should be a no-op.

    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;
    int result;
    const char* error_message = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    result = ebpf_program_load(
        SAMPLE_PATH "test_sample_ebpf.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_INTERPRET,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);

    // Close program handle. That should not detach the program from the hook
    // and should not unload the program.
    bpf_object__close(unique_object.release());
    uint32_t program_id;
    REQUIRE(bpf_prog_get_next_id(0, &program_id) == 0);

    // Detach and close link handle.
    // ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.detach_and_close_link(&link);

    // Program should be unloaded.
    REQUIRE(bpf_prog_get_next_id(0, &program_id) == -ENOENT);
}

#endif

TEST_CASE("create_map", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    fd_t map_fd;
    uint32_t key = 0;
    uint64_t value = 10;
    int element_count = 2;

    map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint64_t), 5, nullptr);
    REQUIRE(map_fd > 0);

    for (int i = 0; i < element_count; i++) {
        REQUIRE(bpf_map_update_elem(map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);
        key++;
        value++;
    }

    key = 0;
    value = 10;
    for (int i = 0; i < element_count; i++) {
        uint64_t read_value;
        REQUIRE(bpf_map_lookup_elem(map_fd, &key, &read_value) == EBPF_SUCCESS);
        REQUIRE(read_value == value);
        key++;
        value++;
    }

    Platform::_close(map_fd);
}

TEST_CASE("create_map_name", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    fd_t map_fd;
    uint32_t key = 0;
    uint64_t value = 10;
    int element_count = 2;
    const char* map_name = "array_map";

    map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, map_name, sizeof(uint32_t), sizeof(uint64_t), 5, nullptr);
    REQUIRE(map_fd > 0);

    for (int i = 0; i < element_count; i++) {
        REQUIRE(bpf_map_update_elem(map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);
        key++;
        value++;
    }

    key = 0;
    value = 10;
    for (int i = 0; i < element_count; i++) {
        uint64_t read_value;
        REQUIRE(bpf_map_lookup_elem(map_fd, &key, &read_value) == EBPF_SUCCESS);
        REQUIRE(read_value == value);
        key++;
        value++;
    }

    Platform::_close(map_fd);
}

TEST_CASE("array_of_maps_large_index_test", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // Create an inner map that we'll use as a template and values.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "inner_map", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    // Create additional inner maps to use as values for testing.
    int inner_map_fd2 =
        bpf_map_create(BPF_MAP_TYPE_ARRAY, "inner_map2", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(inner_map_fd2 > 0);

    int inner_map_fd3 =
        bpf_map_create(BPF_MAP_TYPE_ARRAY, "inner_map3", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(inner_map_fd3 > 0);

    // Create an array-of-maps with 1000 entries to test indices > 255.
    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd};
    int outer_map_fd =
        bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "large_array_of_maps", sizeof(uint32_t), sizeof(fd_t), 1000, &opts);
    REQUIRE(outer_map_fd > 0);

    // Test updating at various indices including ones > 255.
    uint32_t test_indices[] = {0, 255, 256, 300, 500, 999};
    fd_t test_map_fds[] = {inner_map_fd, inner_map_fd2, inner_map_fd3, inner_map_fd, inner_map_fd2, inner_map_fd3};
    size_t test_count = sizeof(test_indices) / sizeof(test_indices[0]);

    // Update entries at test indices - this exercises _update_array_map_entry_with_handle.
    for (size_t i = 0; i < test_count; i++) {
        uint32_t key = test_indices[i];
        fd_t value_fd = test_map_fds[i];
        REQUIRE(bpf_map_update_elem(outer_map_fd, &key, &value_fd, 0) == 0);
    }

    // Verify entries were stored correctly.
    for (size_t i = 0; i < test_count; i++) {
        uint32_t key = test_indices[i];
        ebpf_id_t stored_map_id;
        REQUIRE(bpf_map_lookup_elem(outer_map_fd, &key, &stored_map_id) == 0);

        // Verify we can get the map FD from the stored ID.
        int retrieved_fd = bpf_map_get_fd_by_id(stored_map_id);
        REQUIRE(retrieved_fd > 0);
        Platform::_close(retrieved_fd);
    }

    Platform::_close(inner_map_fd);
    Platform::_close(inner_map_fd2);
    Platform::_close(inner_map_fd3);
    Platform::_close(outer_map_fd);
}

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("printk", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);
    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper;
    program_helper.initialize(
        SAMPLE_PATH "printk.o", BPF_PROG_TYPE_BIND, "func", EBPF_EXECUTION_INTERPRET, &ifindex, sizeof(ifindex), hook);

    // The current bind hook only works with IPv4, so compose a sample IPv4 context.
    SOCKADDR_IN addr = {AF_INET};
    addr.sin_port = htons(80);
    INITIALIZE_BIND_CONTEXT
    ctx->process_id = GetCurrentProcessId();
    ctx->protocol = 2;
    ctx->socket_address_length = sizeof(addr);
    memcpy(&ctx->socket_address, &addr, ctx->socket_address_length);

    capture_helper_t capture;
    std::vector<std::string> output;
    uint32_t hook_result = 0;
    errno_t error = capture.begin_capture();
    if (error == NO_ERROR) {
        usersim_trace_logging_set_enabled(true, EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_PRINTK);
#pragma warning(suppress : 28193) // hook_fire_result is examined
        ebpf_result_t hook_fire_result = hook.fire(ctx, &hook_result);
        usersim_trace_logging_set_enabled(false, 0, 0);

        output = capture.buffer_to_printk_vector(capture.get_stdout_contents());
        REQUIRE(hook_fire_result == EBPF_SUCCESS);
    }
    std::vector<std::string> expected_output = {
        "Hello, world",
        "Hello, world",
        "PID: " + std::to_string(ctx->process_id) + " using %u",
        "PID: " + std::to_string(ctx->process_id) + " using %lu",
        "PID: " + std::to_string(ctx->process_id) + " using %llu",
        "PID: " + std::to_string(ctx->process_id) + " PROTO: 2",
        "PID: " + std::to_string(ctx->process_id) + " PROTO: 2 ADDRLEN: 16",
        "100% done"};
    REQUIRE(output.size() == expected_output.size());
    size_t output_length = 0;
    for (int i = 0; i < output.size(); i++) {
        REQUIRE(output[i] == expected_output[i]);
        output_length += output[i].length();
    }

    // Six of the printf calls in the program should fail and return -1
    // so subtract 6 from the length to get the expected return value.
    REQUIRE(hook_result == output_length - 6);
}
#endif

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("link_tests", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    program_load_attach_helper_t program_helper;
    program_helper.initialize(
        SAMPLE_PATH "bpf.o", BPF_PROG_TYPE_SAMPLE, "func", EBPF_EXECUTION_INTERPRET, nullptr, 0, hook);

    // Dummy context (not used by the eBPF program).
    INITIALIZE_SAMPLE_CONTEXT
    uint32_t result;

    REQUIRE(hook.fire(ctx, &result) == EBPF_SUCCESS);
    bpf_program* program = bpf_object__find_program_by_name(program_helper.get_object(), "func");
    REQUIRE(program != nullptr);

    // Test the case where the provider only permits a single program to be attached.
    REQUIRE(hook.attach(program) == EBPF_EXTENSION_FAILED_TO_LOAD);

    hook.detach();
}
#endif

static void
_map_reuse_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_um.dll" : "map_reuse.o");

    // First create and pin the maps manually.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd};
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), sizeof(fd_t), 1, &opts);
    REQUIRE(outer_map_fd > 0);

    // Verify we can insert the inner map into the outer map.
    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Pin the outer map.
    error = bpf_obj_pin(outer_map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    // The outer map name created above should not have a name.
    bpf_map_info info;
    uint32_t info_size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(outer_map_fd, &info, &info_size) == 0);
    REQUIRE(info.name[0] == 0);

    int port_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(port_map_fd > 0);

    // Pin port map.
    error = bpf_obj_pin(port_map_fd, "/ebpf/global/port_map");
    REQUIRE(error == 0);

    // Add an entry in the inner map.
    __u32 key = 0;
    __u32 value = 200;
    error = bpf_map_update_elem(inner_map_fd, &key, &value, BPF_ANY);
    REQUIRE(error == 0);

    program_load_attach_helper_t program_helper;
    program_helper.initialize(file_name, BPF_PROG_TYPE_SAMPLE, "lookup_update", EBPF_EXECUTION_ANY, nullptr, 0, hook);

    // The outer map we created earlier should still not have a name even though there is a name in the file,
    // since the unnamed map was reused.
    REQUIRE(bpf_obj_get_info_by_fd(outer_map_fd, &info, &info_size) == 0);
    REQUIRE(info.name[0] == 0);

    INITIALIZE_SAMPLE_CONTEXT
    uint32_t hook_result = 0;

    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 200);

    key = 0;
    __u32 port_map_value;
    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &port_map_value) == EBPF_SUCCESS);
    REQUIRE(port_map_value == 200);

    REQUIRE(get_total_map_count() == 4);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("map_reuse", "[end_to_end]", _map_reuse_test);

// Try to reuse a map of the wrong type.
static void
_wrong_map_reuse_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_um.dll" : "map_reuse.o");

    // First create and pin the maps manually.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd};
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), sizeof(fd_t), 1, &opts);
    REQUIRE(outer_map_fd > 0);

    // Pin the outer map and port map to the wrong paths so they won't match what is in the ebpf program.
    REQUIRE(bpf_obj_pin(outer_map_fd, "/ebpf/global/port_map") == 0);

    int port_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(port_map_fd > 0);

    // Pin port map.
    REQUIRE(bpf_obj_pin(port_map_fd, "/ebpf/global/outer_map") == 0);

    // Open eBPF program file.
    bpf_object_ptr object;
    {
        bpf_object* local_object = bpf_object__open(file_name);
        REQUIRE(local_object != nullptr);
        object.reset(local_object);
    }
    bpf_program* program = bpf_object__next_program(object.get(), nullptr);
    REQUIRE(program != nullptr);

    // Try to load the program.  This should fail because the maps can't be reused.
    REQUIRE(bpf_object__load(object.get()) == -EINVAL);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("wrong_map_reuse", "[end_to_end]", _wrong_map_reuse_test);

static void
_auto_pinned_maps_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_um.dll" : "map_reuse.o");

    program_load_attach_helper_t program_helper;
    program_helper.initialize(file_name, BPF_PROG_TYPE_SAMPLE, "lookup_update", EBPF_EXECUTION_ANY, nullptr, 0, hook);

    fd_t outer_map_fd = bpf_obj_get("/ebpf/global/outer_map");
    REQUIRE(outer_map_fd > 0);

    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Add an entry in the inner map.
    __u32 key = 0;
    __u32 value = 200;
    error = bpf_map_update_elem(inner_map_fd, &key, &value, BPF_ANY);
    REQUIRE(error == 0);

    fd_t port_map_fd = bpf_obj_get("/ebpf/global/port_map");
    REQUIRE(port_map_fd > 0);

    INITIALIZE_SAMPLE_CONTEXT
    uint32_t hook_result = 0;

    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 200);

    key = 0;
    __u32 port_map_value;
    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &port_map_value) == EBPF_SUCCESS);
    REQUIRE(port_map_value == 200);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("auto_pinned_maps", "[end_to_end]", _auto_pinned_maps_test);

static void
_map_reuse_invalid_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    // Create and pin a map with a different map type than in ELF file.
    int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(map_fd > 0);

    // Pin the map.
    int error = bpf_obj_pin(map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    int port_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(port_map_fd > 0);

    // Pin port map.
    error = bpf_obj_pin(port_map_fd, "/ebpf/global/port_map");
    REQUIRE(error == 0);

    // Load BPF object from ELF file. Loading the program should fail as the
    // map type for map pinned at "/ebpf/global/outer_map" does not match.
    bpf_object_ptr unique_object;
    fd_t program_fd;
    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_um.dll" : "map_reuse.o");
    int result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_ANY, &unique_object, &program_fd, nullptr);

    REQUIRE(result == -EINVAL);

    Platform::_close(map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("map_reuse_invalid", "[end_to_end]", _map_reuse_invalid_test);

static void
_map_reuse_2_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_2_um.dll" : "map_reuse_2.o");

    // First create and pin the maps manually.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd};
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), sizeof(fd_t), 1, &opts);
    REQUIRE(outer_map_fd > 0);

    // Verify we can insert the inner map into the outer map.
    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Pin the outer map.
    error = bpf_obj_pin(outer_map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    int port_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(outer_map_fd > 0);

    // Pin port map.
    error = bpf_obj_pin(port_map_fd, "/ebpf/global/port_map");
    REQUIRE(error == 0);

    // Add an entry in the inner map.
    __u32 key = 0;
    __u32 value = 200;
    error = bpf_map_update_elem(inner_map_fd, &key, &value, BPF_ANY);
    REQUIRE(error == 0);

    program_load_attach_helper_t program_helper;
    program_helper.initialize(file_name, BPF_PROG_TYPE_SAMPLE, "lookup_update", EBPF_EXECUTION_ANY, nullptr, 0, hook);

    INITIALIZE_SAMPLE_CONTEXT
    uint32_t hook_result = 0;

    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 200);

    key = 0;
    __u32 port_map_value;
    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &port_map_value) == EBPF_SUCCESS);
    REQUIRE(port_map_value == 200);

    REQUIRE(get_total_map_count() == 4);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    // The below two objects were pinned by this UM test.
    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);

    // This object was auto-pinned while loading the program.
    REQUIRE(ebpf_object_unpin("/ebpf/global/inner_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("map_reuse_2", "[end_to_end]", _map_reuse_2_test);

static void
_map_reuse_3_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    // First create and pin the maps manually.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd};
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), sizeof(fd_t), 1, &opts);
    REQUIRE(outer_map_fd > 0);

    // Verify we can insert the inner map into the outer map.
    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Pin the outer map.
    error = bpf_obj_pin(outer_map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    // Pin the inner map.
    error = bpf_obj_pin(inner_map_fd, "/ebpf/global/inner_map");
    REQUIRE(error == 0);

    int port_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(outer_map_fd > 0);

    // Pin port map.
    error = bpf_obj_pin(port_map_fd, "/ebpf/global/port_map");
    REQUIRE(error == 0);

    // Add an entry in the inner map.
    __u32 key = 0;
    __u32 value = 200;
    error = bpf_map_update_elem(inner_map_fd, &key, &value, BPF_ANY);
    REQUIRE(error == 0);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_2_um.dll" : "map_reuse_2.o");

    program_load_attach_helper_t program_helper;
    program_helper.initialize(file_name, BPF_PROG_TYPE_SAMPLE, "lookup_update", EBPF_EXECUTION_ANY, nullptr, 0, hook);

    INITIALIZE_SAMPLE_CONTEXT
    uint32_t hook_result = 0;

    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 200);

    key = 0;
    __u32 port_map_value;
    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &port_map_value) == EBPF_SUCCESS);
    REQUIRE(port_map_value == 200);

    REQUIRE(get_total_map_count() == 3);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/inner_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("map_reuse_3", "[end_to_end]", _map_reuse_3_test);

static void
_create_service_helper(
    _In_z_ const wchar_t* file_name,
    _In_z_ const wchar_t* service_name,
    _In_ const GUID* provider_module_id,
    _Out_ SC_HANDLE* service_handle)
{
    std::wstring parameters_path(PARAMETERS_PATH_PREFIX);

    REQUIRE(Platform::_create_service(service_name, file_name, service_handle) == ERROR_SUCCESS);

    parameters_path = parameters_path + service_name + L"\\" + SERVICE_PARAMETERS;
    REQUIRE(Platform::_create_registry_key(HKEY_LOCAL_MACHINE, parameters_path.c_str()) == ERROR_SUCCESS);

    REQUIRE(
        Platform::_update_registry_value(
            HKEY_LOCAL_MACHINE, parameters_path.c_str(), REG_BINARY, NPI_MODULE_ID, provider_module_id, sizeof(GUID)) ==
        ERROR_SUCCESS);
}

// Load a native module with non-existing driver.
TEST_CASE("load_native_program_negative", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    GUID provider_module_id;
    SC_HANDLE service_handle = nullptr;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    ebpf_handle_t module_handle = ebpf_handle_invalid;
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    set_native_module_failures(true);

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    // Creating valid service with non-existing driver.
    _create_service_helper(L"fake_program.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    // Load native module. It should fail.
    service_path = service_path + NATIVE_DRIVER_SERVICE_NAME;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path, &provider_module_id, &module_handle, &count_of_maps, &count_of_programs) ==
        ERROR_PATH_NOT_FOUND);
}

// Load native module by passing invalid service name to EC.
TEST_CASE("load_native_program_negative2", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    GUID provider_module_id;
    SC_HANDLE service_handle = nullptr;
    std::wstring service_path(L"");
    ebpf_handle_t module_handle = ebpf_handle_invalid;
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    set_native_module_failures(true);

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    _create_service_helper(
        L"test_sample_ebpf_um.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    // Create invalid service path and pass to EC.
    service_path += NATIVE_DRIVER_SERVICE_NAME_2;

    // Load native module. It should fail.
    REQUIRE(
        test_ioctl_load_native_module(
            service_path, &provider_module_id, &module_handle, &count_of_maps, &count_of_programs) ==
        ERROR_PATH_NOT_FOUND);
}

// Load native module and then try to reload the same module.
TEST_CASE("load_native_program_negative3", "[end-to-end]")
{
#define MAP_COUNT 2
#define PROGRAM_COUNT 1
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    GUID provider_module_id = GUID_NULL;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    int error;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    std::wstring file_path(L"test_sample_ebpf_um.dll");
    const wchar_t* service_name = nullptr;
    ebpf_handle_t module_handle = ebpf_handle_invalid;
    ebpf_handle_t map_handles[MAP_COUNT];
    ebpf_handle_t program_handles[PROGRAM_COUNT];

    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    // Load a valid native module.
    error = ebpf_program_load(
        "test_sample_ebpf_um.dll",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_NATIVE,
        &unique_object,
        &program_fd,
        &error_message);
    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(error == 0);

    // Get the service name that was created.
    REQUIRE(get_service_details_for_file(file_path, &service_name, &provider_module_id) == EBPF_SUCCESS);

    set_native_module_failures(true);

    // Try to reload the same native module. It should fail.
    service_path = service_path + service_name;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path, &provider_module_id, &module_handle, &count_of_maps, &count_of_programs) ==
        ERROR_OBJECT_ALREADY_EXISTS);

    // Try to load the programs from the same module again. It should fail.
    REQUIRE(
        test_ioctl_load_native_programs(&provider_module_id, MAP_COUNT, map_handles, PROGRAM_COUNT, program_handles) ==
        ERROR_OBJECT_ALREADY_EXISTS);

    bpf_object__close(unique_object.release());

    // Now that we have closed the object, try to load programs from the same module again. This should
    // fail as the module should now be marked as "unloading".
    REQUIRE(
        test_ioctl_load_native_programs(&provider_module_id, MAP_COUNT, map_handles, PROGRAM_COUNT, program_handles) !=
        ERROR_SUCCESS);
}

// Load native module and then try to load programs with incorrect params.
TEST_CASE("load_native_program_negative4", "[end-to-end]")
{
#define PROGRAM_COUNT 1
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    GUID provider_module_id = GUID_NULL;
    SC_HANDLE service_handle = nullptr;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    std::wstring file_path(L"test_sample_ebpf_um.dll");
    _test_handle_helper module_handle;
    ebpf_handle_t program_handles[PROGRAM_COUNT];

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    // First try to load native program without loading the native module.
    REQUIRE(
        test_ioctl_load_native_programs(&provider_module_id, 0, nullptr, PROGRAM_COUNT, program_handles) ==
        ERROR_PATH_NOT_FOUND);

    // Creating valid service with valid driver.
    _create_service_helper(
        L"test_sample_ebpf_um.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    REQUIRE(ebpf_authorize_native_module_wrapper(&provider_module_id, "test_sample_ebpf_um.dll") == EBPF_SUCCESS);

    // Load native module. It should succeed.
    service_path = service_path + NATIVE_DRIVER_SERVICE_NAME;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path,
            &provider_module_id,
            module_handle.get_handle_pointer(),
            &count_of_maps,
            &count_of_programs) == ERROR_SUCCESS);

    // Try to load the programs by passing wrong map and program handles size. This should fail.
    REQUIRE(
        test_ioctl_load_native_programs(&provider_module_id, 0, nullptr, PROGRAM_COUNT, program_handles) ==
        ERROR_INVALID_PARAMETER);

    // Delete the created service.
    Platform::_delete_service(service_handle);
}

// Try to load a .sys in user mode.
TEST_CASE("load_native_program_negative5", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    set_native_module_failures(true);
    result = ebpf_program_load(
        "map.sys", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, &unique_object, &program_fd, &error_message);
    REQUIRE(result == -ENOENT);
}

// Load native module twice.
TEST_CASE("load_native_program_negative6", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    GUID provider_module_id;
    SC_HANDLE service_handle = nullptr;
    SC_HANDLE service_handle2 = nullptr;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    std::wstring service_path2(SERVICE_PATH_PREFIX);
    _test_handle_helper module_handle;
    _test_handle_helper module_handle2;
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    set_native_module_failures(true);

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    // Create a valid service with valid driver.
    _create_service_helper(
        L"test_sample_ebpf_um.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    REQUIRE(ebpf_authorize_native_module_wrapper(&provider_module_id, "test_sample_ebpf_um.dll") == EBPF_SUCCESS);

    // Load native module. It should succeed.
    service_path = service_path + NATIVE_DRIVER_SERVICE_NAME;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path,
            &provider_module_id,
            module_handle.get_handle_pointer(),
            &count_of_maps,
            &count_of_programs) == ERROR_SUCCESS);

    // Create a new service with same driver and same module id.
    _create_service_helper(
        L"test_sample_ebpf_um.dll", NATIVE_DRIVER_SERVICE_NAME_2, &provider_module_id, &service_handle2);

    set_native_module_failures(true);

    // Load native module. It should fail.
    service_path2 = service_path2 + NATIVE_DRIVER_SERVICE_NAME_2;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path2,
            &provider_module_id,
            module_handle2.get_handle_pointer(),
            &count_of_maps,
            &count_of_programs) == ERROR_OBJECT_ALREADY_EXISTS);
}

// Verify that stale module entries are removed.
TEST_CASE("load_native_program_negative7", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    GUID provider_module_id;
    SC_HANDLE service_handle = nullptr;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    std::wstring service_path2(SERVICE_PATH_PREFIX);
    _test_handle_helper module_handle;
    _test_handle_helper module_handle2;
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    set_native_module_failures(true);

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    // Create a valid service with valid driver.
    _create_service_helper(
        L"test_sample_ebpf_um.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    REQUIRE(ebpf_authorize_native_module_wrapper(&provider_module_id, "test_sample_ebpf_um.dll") == EBPF_SUCCESS);

    // Wait for authorization to expire.
    std::this_thread::sleep_for(std::chrono::seconds(20));

    // Load native module. It should fail as the authorization has expired.
    service_path = service_path + NATIVE_DRIVER_SERVICE_NAME;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path,
            &provider_module_id,
            module_handle.get_handle_pointer(),
            &count_of_maps,
            &count_of_programs) != ERROR_SUCCESS);
}

extern bool _ebpf_platform_code_integrity_test_signing_enabled;

// Wrong signature.
TEST_CASE("load_native_program_negative8", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;
    GUID provider_module_id;
    _ebpf_platform_code_integrity_test_signing_enabled = false;
    test_helper.initialize();
    _ebpf_platform_code_integrity_test_signing_enabled = true;

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);
    ebpf_result_t result = ebpf_authorize_native_module_wrapper(&provider_module_id, "test_sample_ebpf_um.dll");

    REQUIRE(result != EBPF_SUCCESS);
}

// Load native module and then use module handle for a different purpose.
TEST_CASE("native_module_handle_test_negative", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    GUID provider_module_id;
    SC_HANDLE service_handle = nullptr;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    ebpf_handle_t module_handle = ebpf_handle_invalid;
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    set_native_module_failures(true);

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    // Create a valid service with valid driver.
    _create_service_helper(
        L"test_sample_ebpf_um.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    REQUIRE(ebpf_authorize_native_module_wrapper(&provider_module_id, "test_sample_ebpf_um.dll") == EBPF_SUCCESS);

    // Load native module. It should succeed.
    service_path = service_path + NATIVE_DRIVER_SERVICE_NAME;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path, &provider_module_id, &module_handle, &count_of_maps, &count_of_programs) == ERROR_SUCCESS);

    // Create an fd for the module handle.
    fd_t module_fd = Platform::_open_osfhandle(module_handle, 0);
    REQUIRE(module_fd != ebpf_fd_invalid);

    // Try to use the native module fd as a program or map fd.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(module_fd, &program_info, &program_info_size) == -EINVAL);

    Platform::_close(module_fd);
}

TEST_CASE("ebpf_get_program_type_by_name invalid name", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;

    REQUIRE(ebpf_get_program_type_by_name("invalid_name", &program_type, &attach_type) == EBPF_KEY_NOT_FOUND);
}

TEST_CASE("ebpf_get_program_type_name invalid types", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    ebpf_program_type_t program_type = EBPF_PROGRAM_TYPE_UNSPECIFIED;

    // First try with EBPF_PROGRAM_TYPE_UNSPECIFIED.
    const char* name1 = ebpf_get_program_type_name(&program_type);
    REQUIRE(name1 == nullptr);

    // Try with a random program type GUID.
    REQUIRE(UuidCreate(&program_type) == RPC_S_OK);
    const char* name2 = ebpf_get_program_type_name(&program_type);
    REQUIRE(name2 == nullptr);
}

TEST_CASE("ebpf_get_ebpf_attach_type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // First test a valid input.
    ebpf_attach_type_t attach_type;
    REQUIRE(ebpf_get_ebpf_attach_type(BPF_ATTACH_TYPE_BIND, &attach_type) == EBPF_SUCCESS);

    REQUIRE(IsEqualGUID(attach_type, EBPF_ATTACH_TYPE_BIND) != 0);

    // Try with invalid bpf attach type.
    REQUIRE(
        ebpf_get_ebpf_attach_type((bpf_attach_type_t)BPF_ATTACH_TYPE_INVALID, &attach_type) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("ebpf_get_bpf_program_type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // First test a valid input.
    REQUIRE(ebpf_get_bpf_program_type(&EBPF_PROGRAM_TYPE_SAMPLE) == BPF_PROG_TYPE_SAMPLE);

    // Try with EBPF_PROGRAM_TYPE_UNSPECIFIED.
    REQUIRE(ebpf_get_bpf_program_type(&EBPF_PROGRAM_TYPE_UNSPECIFIED) == BPF_PROG_TYPE_UNSPEC);

    // Try with invalid program type.
    GUID invalid_program_type;
    REQUIRE(UuidCreate(&invalid_program_type) == RPC_S_OK);
    REQUIRE(ebpf_get_bpf_program_type(&invalid_program_type) == BPF_PROG_TYPE_UNSPEC);
}

TEST_CASE("ebpf_get_ebpf_program_type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // Try with BPF_PROG_TYPE_UNSPEC.
    const ebpf_program_type_t* program_type = ebpf_get_ebpf_program_type(BPF_PROG_TYPE_UNSPEC);
    REQUIRE(program_type != nullptr);
    REQUIRE(IsEqualGUID(EBPF_PROGRAM_TYPE_UNSPECIFIED, *program_type) != 0);

    // Try a valid bpf prog type.
    program_type = ebpf_get_ebpf_program_type(BPF_PROG_TYPE_SAMPLE);
    REQUIRE(program_type != nullptr);
    REQUIRE(IsEqualGUID(EBPF_PROGRAM_TYPE_SAMPLE, *program_type) != 0);

    // Try an invalid bpf prog type.
    program_type = ebpf_get_ebpf_program_type((bpf_prog_type_t)BPF_PROG_TYPE_INVALID);
    REQUIRE(program_type == nullptr);
}

TEST_CASE("ebpf_get_bpf_attach_type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // Try with EBPF_ATTACH_TYPE_SAMPLE.
    REQUIRE(ebpf_get_bpf_attach_type(&EBPF_ATTACH_TYPE_SAMPLE) == BPF_ATTACH_TYPE_SAMPLE);

    // Try with EBPF_ATTACH_TYPE_UNSPECIFIED.
    REQUIRE(ebpf_get_bpf_attach_type(&EBPF_ATTACH_TYPE_UNSPECIFIED) == BPF_ATTACH_TYPE_UNSPEC);

    // Try with invalid attach type.
    GUID invalid_attach_type;
    REQUIRE(UuidCreate(&invalid_attach_type) == RPC_S_OK);
    REQUIRE(ebpf_get_bpf_attach_type(&invalid_attach_type) == BPF_ATTACH_TYPE_UNSPEC);
}

TEST_CASE("test_ebpf_object_set_execution_type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // First open a .dll file
    bpf_object* native_object = bpf_object__open("test_sample_ebpf_um.dll");
    REQUIRE(native_object != nullptr);

    // Try to set incorrect execution type.
    REQUIRE(ebpf_object_set_execution_type(native_object, EBPF_EXECUTION_JIT) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_object_set_execution_type(native_object, EBPF_EXECUTION_INTERPRET) == EBPF_INVALID_ARGUMENT);

    // The following should succeed.
    REQUIRE(ebpf_object_set_execution_type(native_object, EBPF_EXECUTION_ANY) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get_execution_type(native_object) == EBPF_EXECUTION_NATIVE);
    REQUIRE(ebpf_object_set_execution_type(native_object, EBPF_EXECUTION_NATIVE) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get_execution_type(native_object) == EBPF_EXECUTION_NATIVE);

    bpf_object__close(native_object);

    // Open a .o file
    bpf_object* jit_object = bpf_object__open("test_sample_ebpf.o");
    REQUIRE(jit_object != nullptr);

    // Try to set incorrect execution type.
    REQUIRE(ebpf_object_set_execution_type(jit_object, EBPF_EXECUTION_NATIVE) == EBPF_INVALID_ARGUMENT);

    // The following should succeed.
    REQUIRE(ebpf_object_set_execution_type(jit_object, EBPF_EXECUTION_ANY) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get_execution_type(jit_object) == EBPF_EXECUTION_JIT);
    REQUIRE(ebpf_object_set_execution_type(jit_object, EBPF_EXECUTION_JIT) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get_execution_type(jit_object) == EBPF_EXECUTION_JIT);
    REQUIRE(ebpf_object_set_execution_type(jit_object, EBPF_EXECUTION_INTERPRET) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get_execution_type(jit_object) == EBPF_EXECUTION_INTERPRET);

    bpf_object__close(jit_object);
}

static void
extension_reload_test_common(_In_ const char* file_name, ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // Empty context (not used by the eBPF program).
    INITIALIZE_SAMPLE_CONTEXT

    // Try loading without the extension loaded.
    bpf_object_ptr unique_test_sample_ebpf_object;
    bpf_link_ptr link;
    int program_fd = -1;
    const char* error_message = nullptr;
    int result;

    // Should fail.
    REQUIRE(
        ebpf_program_load(
            file_name,
            BPF_PROG_TYPE_UNSPEC,
            execution_type,
            &unique_test_sample_ebpf_object,
            &program_fd,
            &error_message) != 0);

    ebpf_free((void*)error_message);

    // Load the program with the extension loaded.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        program_info_provider_t sample_program_info;
        REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

        result = ebpf_program_load(
            file_name,
            BPF_PROG_TYPE_UNSPEC,
            execution_type,
            &unique_test_sample_ebpf_object,
            &program_fd,
            &error_message);

        if (error_message) {
            printf("ebpf_program_load failed with %s\n", error_message);
            ebpf_free((void*)error_message);
        }
        REQUIRE(result == 0);

        bpf_link* raw_link = nullptr;
        // Attach only to the single interface being tested.
        REQUIRE(hook.attach_link(program_fd, nullptr, 0, &raw_link) == EBPF_SUCCESS);
        link.reset(raw_link);

        // Program should run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
        REQUIRE(hook_result == 42);

        // Unload the extension (sample_program_info and hook will be destroyed).
    }

    // Reload the extension provider with unchanged data.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        program_info_provider_t sample_program_info;
        REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

        // Program should re-attach to the hook.

        // Program should run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
        REQUIRE(hook_result == 42);
    }

    // Reload the extension provider with missing helper function.
    {
        ebpf_helper_function_addresses_t changed_helper_function_address_table = {
            .header = EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
            .helper_function_count = 0,
            .helper_function_address = nullptr};
        ebpf_program_data_t changed_program_data = _test_ebpf_sample_extension_program_data;
        changed_program_data.program_type_specific_helper_function_addresses = &changed_helper_function_address_table;

        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        program_info_provider_t sample_program_info;
        REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE, &changed_program_data) == EBPF_SUCCESS);

        // Program should re-attach to the hook.

        // Program should not run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(ctx, &hook_result) != EBPF_SUCCESS);
        REQUIRE(hook_result != 42);
    }

    // Reload the extension provider with changed helper function data.
    {
        ebpf_helper_function_prototype_t
            helper_function_prototypes[EBPF_COUNT_OF(_sample_ebpf_extension_helper_function_prototype)];
        std::copy(
            _sample_ebpf_extension_helper_function_prototype,
            _sample_ebpf_extension_helper_function_prototype +
                EBPF_COUNT_OF(_sample_ebpf_extension_helper_function_prototype),
            helper_function_prototypes);
        // Change the return type of the helper function from EBPF_RETURN_TYPE_INTEGER to
        // EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL.
        helper_function_prototypes[0].return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL;
        ebpf_program_info_t changed_program_info = _sample_ebpf_extension_program_info;
        changed_program_info.program_type_specific_helper_prototype = helper_function_prototypes;
        ebpf_program_data_t changed_program_data = _test_ebpf_sample_extension_program_data;
        changed_program_data.program_info = &changed_program_info;

        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        program_info_provider_t sample_program_info;
        REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE, &changed_program_data) == EBPF_SUCCESS);

        // Program should re-attach to the hook.

        // Program should not run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(ctx, &hook_result) != EBPF_SUCCESS);
        REQUIRE(hook_result != 42);
    }

    // Reload the extension again with original data.
    {
        ebpf_program_data_t changed_program_data = _test_ebpf_sample_extension_program_data;

        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        program_info_provider_t sample_program_info;
        REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE, &changed_program_data) == EBPF_SUCCESS);

        // Program should re-attach to the hook.

        // Program should run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
        REQUIRE(hook_result == 42);
    }

    // Reload the extension with non-zero reserved bits in capabilities.
    {
        ebpf_program_data_t changed_program_data = _test_ebpf_sample_extension_program_data;
        changed_program_data.capabilities.reserved = 1;

        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        program_info_provider_t sample_program_info;
        REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE, &changed_program_data) == EBPF_SUCCESS);

        // Program should re-attach to the hook.

        // Program should not run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(ctx, &hook_result) != EBPF_SUCCESS);
        REQUIRE(hook_result != 42);
    }

    // Reload the extension again with original data
    {
        ebpf_program_data_t changed_program_data = _test_ebpf_sample_extension_program_data;

        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        program_info_provider_t sample_program_info;
        REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE, &changed_program_data) == EBPF_SUCCESS);

        // Program should re-attach to the hook.

        // Program should run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
        REQUIRE(hook_result == 42);
    }
}

static void
extension_reload_test(ebpf_execution_type_t execution_type)
{
    const char* file_name = execution_type == EBPF_EXECUTION_NATIVE ? "test_sample_ebpf_um.dll" : "test_sample_ebpf.o";
    extension_reload_test_common(file_name, execution_type);
}

DECLARE_ALL_TEST_CASES("extension_reload_test", "[end_to_end]", extension_reload_test);

static void
_extension_reload_test_implicit_context(ebpf_execution_type_t execution_type)
{
    const char* file_name = execution_type == EBPF_EXECUTION_NATIVE ? "test_sample_implicit_helpers_um.dll"
                                                                    : "test_sample_implicit_helpers.o";
    extension_reload_test_common(file_name, execution_type);
}

DECLARE_ALL_TEST_CASES(
    "extension_reload_test_implicit_context", "[end_to_end]", _extension_reload_test_implicit_context);

// This test tests resource reclamation and clean-up after a premature/abnormal user mode application exit.
TEST_CASE("close_unload_test", "[close_cleanup]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;

    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    const char* file_name = "bindmonitor_tailcall_um.dll";
    result = ebpf_program_load(
        file_name, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        free((void*)error_message);
    }
    REQUIRE(result == 0);

    // Set up tail calls.
    struct bpf_program* callee0 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "prog_array_map");
    REQUIRE(prog_map_fd > 0);

    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // These are needed to prevent the memory leak detector from flagging a memory leak.
    hook.detach_and_close_link(&link);

    // The block of commented code after this comment is for documentation purposes only.
    //
    // A well-behaved user mode application _should_ call these calls to correctly free the allocated objects. In case
    // of careless applications that do not do so (or even well behaved applications, when they crash or terminate for
    // some reason before getting to this point), the 'premature application close' event handling _should_ take care
    // of reclaiming and free'ing such objects.
    //
    // In a user-mode unit test case such as this one, the 'premature application close' event is simulated/handled in
    // the context of the bpf_object__close() api, so a call to that api is mandatory for such tests.  All unit tests
    // belonging to the '[close_cleanup]' unit-test class will show this behavior.
    //
    // For an identical test meant for execution on the native (kernel mode ebpf-for-windows driver), this event will
    // be handled by the kernel mode driver on test application termination.  Such a test application _should_ _not_
    // call bpf_object__close() api either.
    //

    /*
       --- DO NOT REMOVE OR UN-COMMENT ---
    //
    // index = 0;
    // REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    //
    // index = 1;
    // REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    */

    bpf_object__close(unique_object.release());
}

// This test tests the case where a program is inserted multiple times with different keys into the same map.
TEST_CASE("multiple_map_insert", "[close_cleanup]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;

    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    const char* file_name = "bindmonitor_tailcall_um.dll";
    result = ebpf_program_load(
        file_name, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        free((void*)error_message);
    }
    REQUIRE(result == 0);

    // Set up tail calls.
    struct bpf_program* callee0 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "prog_array_map");
    REQUIRE(prog_map_fd > 0);

    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);

    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    // Insert the same program for multiple keys in the same map.
    index = 2;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    index = 4;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    index = 7;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // These are needed to prevent the memory leak detector from flagging a memory leak.
    hook.detach_and_close_link(&link);

    /*
       --- DO NOT REMOVE OR UN-COMMENT ---
    // Please refer to the detailed comment in the 'close_unload_test' test for explanation.
    //
    // index = 0;
    // REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    //
    // index = 1;
    // REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    */

    bpf_object__close(unique_object.release());
}

void
test_no_limit_map_entries(ebpf_map_type_t type, bool max_entries_limited)
{
    uint32_t max_entries = 2;
    fd_t inner_map_fd = ebpf_fd_invalid;
    fd_t map_fd = ebpf_fd_invalid;
    void* value = nullptr;
    uint32_t key_size = 0;
    uint32_t value_size = 0;
    void* key = nullptr;

#define IS_LRU_MAP(type) ((type) == BPF_MAP_TYPE_LRU_HASH || (type) == BPF_MAP_TYPE_LRU_PERCPU_HASH)
#define IS_PERCPU_MAP(type) ((type) == BPF_MAP_TYPE_PERCPU_HASH || (type) == BPF_MAP_TYPE_LRU_PERCPU_HASH)
#define IS_LPM_MAP(type) ((type) == BPF_MAP_TYPE_LPM_TRIE)
#define IS_NESTED_MAP(type) ((type) == BPF_MAP_TYPE_HASH_OF_MAPS)

    typedef struct _lpm_trie_key
    {
        uint32_t prefix_length;
        uint32_t value;
    } lpm_trie_key_t;

    lpm_trie_key_t trie_key = {0};

    if (IS_NESTED_MAP(type)) {
        // First create and pin the maps manually.
        inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(int32_t), sizeof(int32_t), 1, nullptr);
        REQUIRE(inner_map_fd > 0);

        bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd};
        key_size = sizeof(int32_t);
        value_size = sizeof(fd_t);
        map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, key_size, value_size, 1, &opts);
        REQUIRE(map_fd > 0);
    } else {
        key_size = IS_LPM_MAP(type) ? sizeof(lpm_trie_key_t) : sizeof(int32_t);
        value_size = sizeof(int32_t);
        map_fd = bpf_map_create(type, nullptr, key_size, value_size, max_entries, nullptr);
        REQUIRE(map_fd > 0);
    }

    // Update value_size for percpu maps for read / update operations.
    if (IS_PERCPU_MAP(type)) {
        value_size = EBPF_PAD_8(value_size) * static_cast<size_t>(libbpf_num_possible_cpus());
    }
    std::vector<uint8_t> per_cpu_value(value_size);

    auto compute_key = [&](uint32_t* i) -> void* {
        if (IS_LPM_MAP(type)) {
            trie_key.prefix_length = 32;
            trie_key.value = *i;
            return &trie_key;
        } else {
            return i;
        }
    };

    // Add `max_entries` entries to the map.
    for (uint32_t i = 0; i < max_entries; i++) {
        key = compute_key(&i);
        if (IS_PERCPU_MAP(type)) {
            value = per_cpu_value.data();
        } else {
            value = IS_NESTED_MAP(type) ? &inner_map_fd : (int32_t*)&i;
        }
        REQUIRE(bpf_map_update_elem(map_fd, key, value, 0) == 0);
    }

    // Add one more entry to the map.
    if (IS_PERCPU_MAP(type)) {
        value = per_cpu_value.data();
    } else {
        value = IS_NESTED_MAP(type) ? &inner_map_fd : (int32_t*)&max_entries;
    }

    // In case of LRU_HASH, the insert will succeed, but the oldest entry will be removed.
    int expected_error = (!max_entries_limited || IS_LRU_MAP(type)) ? 0 : -ENOSPC;
    key = compute_key(&max_entries);
    REQUIRE(bpf_map_update_elem(map_fd, key, value, 0) == (max_entries_limited ? expected_error : 0));

    // In case of LRU_HASH, check that the number of entries is still `max_entries`.
    if (IS_LRU_MAP(type) && max_entries_limited) {
        uint32_t entries_count = 0;
        lpm_trie_key_t local_key = {0};
        void* old_key = nullptr;
        void* next_key = &local_key;

        while (bpf_map_get_next_key(map_fd, old_key, next_key) == 0) {
            old_key = next_key;
            entries_count++;
        }
        REQUIRE(entries_count == max_entries);
    }
}

// This test case tests the map limits of various hash table based map types.
TEST_CASE("test_map_entries_limit", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    // The below hash table based map types do not have a limit on the number of entries.
    // 1. BPF_MAP_TYPE_HASH
    // 2. BPF_MAP_TYPE_PERCPU_HASH
    // 3. BPF_MAP_TYPE_HASH_OF_MAPS
    // 4. BPF_MAP_TYPE_LPM_TRIE
    test_no_limit_map_entries(BPF_MAP_TYPE_HASH, false);
    test_no_limit_map_entries(BPF_MAP_TYPE_PERCPU_HASH, false);
    test_no_limit_map_entries(BPF_MAP_TYPE_HASH_OF_MAPS, false);
    test_no_limit_map_entries(BPF_MAP_TYPE_LPM_TRIE, false);

    // The below hash table based map types have a limit on the number of entries.
    // 1. BPF_MAP_TYPE_LRU_HASH
    // 2. BPF_MAP_TYPE_LRU_PERCPU_HASH
    test_no_limit_map_entries(BPF_MAP_TYPE_LRU_HASH, true);
    test_no_limit_map_entries(BPF_MAP_TYPE_LRU_PERCPU_HASH, true);
}

static void
_implicit_context_helpers_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    INITIALIZE_SAMPLE_CONTEXT
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    uint32_t data1 = 1;
    uint32_t data2 = 2;

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE) ? "test_sample_implicit_helpers_um.dll"
                                                                      : "test_sample_implicit_helpers.o";

    ctx->helper_data_1 = data1;
    ctx->helper_data_2 = data2;

    // Try loading without the extension loaded.
    bpf_object_ptr unique_test_sample_ebpf_object;
    bpf_link_ptr link;
    int program_fd = -1;
    const char* error_message = nullptr;
    int result;

    result = ebpf_program_load(
        file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_test_sample_ebpf_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    // Attach only to the single interface being tested.
    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);

    // Program should run.
    uint32_t hook_result = MAXUINT32;
    REQUIRE(hook.fire(ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 42);

    // Read the output_map and check the values.
    fd_t output_map_fd = bpf_object__find_map_fd_by_name(unique_test_sample_ebpf_object.get(), "output_map");
    REQUIRE(output_map_fd > 0);
    helper_values_t data = {0};
    uint32_t key = 0;
    REQUIRE(bpf_map_lookup_elem(output_map_fd, &key, &data) == 0);
    REQUIRE(data.value_1 == data1);
    REQUIRE(data.value_2 == data2 + 10);
}

DECLARE_ALL_TEST_CASES("implicit_context_helpers_test", "[end_to_end]", _implicit_context_helpers_test);

void
negative_perf_buffer_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "bpf_call_um.dll" : "bpf_call.o");

    // Load eBPF program.
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    fd_t map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "map");
    REQUIRE(map_fd > 0);

    // Calls to perf buffer APIs on this map (array_map) must fail.
    ebpf_perf_buffer_opts perf_opts{.sz = sizeof(perf_opts), .flags = EBPF_PERFBUF_FLAG_AUTO_CALLBACK};
    REQUIRE(
        ebpf_perf_buffer__new(
            map_fd,
            0,
            [](void*, int, void*, uint32_t) { return; },
            [](void*, int, uint64_t) { return; },
            nullptr,
            &perf_opts) == nullptr);
    REQUIRE(libbpf_get_error(nullptr) == EINVAL);
    uint8_t data = 0;
    REQUIRE(ebpf_perf_event_array_map_write(map_fd, &data, sizeof(data)) == EBPF_INVALID_ARGUMENT);
    bpf_object__close(unique_object.release());
}

void
bindmonitor_perf_buffer_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;
    program_info_provider_t bind_program_info;

    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_perf_event_array_um.dll"
                                                 : "bindmonitor_perf_event_array.o");

    // Load and attach a bind eBPF program that uses a perf buffer map to notify about bind operations.
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    fd_t process_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "process_map");
    REQUIRE(process_map_fd > 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);

    // Create a list of fake app IDs and set it to event context.
    std::string fake_app_ids_prefix = "fake_app";
    std::vector<std::vector<char>> fake_app_ids;
    for (int i = 0; i < PERF_BUFFER_TEST_EVENT_COUNT; i++) {
        std::string temp = fake_app_ids_prefix + std::to_string(i);
        std::vector<char> fake_app_id(temp.begin(), temp.end());
        fake_app_ids.push_back(fake_app_id);
    }

    uint64_t fake_pid = 12345;
    std::function<ebpf_result_t(void*, uint32_t*)> invoke =
        [&hook](_Inout_ void* context, _Out_ uint32_t* result) -> ebpf_result_t { return hook.fire(context, result); };

    // Test multiple subscriptions to the same perf buffer, to ensure that the perf buffer map will continue
    // to provide notifications to the subscriber.
    for (int i = 0; i < 3; i++) {
        perf_buffer_api_test_helper(
            process_map_fd,
            fake_app_ids,
            [&](int i) {
                // Emulate bind operation.
                std::vector<char> fake_app_id = fake_app_ids[i];
                fake_app_id.push_back('\0');
                REQUIRE(emulate_bind(invoke, fake_pid + i, fake_app_id.data()) == BIND_PERMIT);
            },
            true);
    }

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

static void
test_sample_perf_buffer_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    INITIALIZE_SAMPLE_CONTEXT
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE) ? "test_sample_perf_event_array_um.dll"
                                                                      : "test_sample_perf_event_array.o";

    // Create a list of fake app IDs and set it to event context.
    std::string fake_app_ids_prefix = "fake_app";
    std::vector<std::vector<char>> fake_app_ids;
    for (int i = 0; i < PERF_BUFFER_TEST_EVENT_COUNT; i++) {
        std::string temp = fake_app_ids_prefix + std::to_string(i);
        std::vector<char> fake_app_id(temp.begin(), temp.end());
        fake_app_ids.push_back(fake_app_id);
    }

    // Try loading without the extension loaded.
    bpf_object_ptr unique_test_sample_ebpf_object;
    int program_fd = -1;
    const char* error_message = nullptr;
    int result;

    result = ebpf_program_load(
        file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_test_sample_ebpf_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    fd_t test_map_fd = bpf_object__find_map_fd_by_name(unique_test_sample_ebpf_object.get(), "test_map");
    REQUIRE(test_map_fd > 0);

    bpf_link_ptr link;
    // Attach only to the single interface being tested.
    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);
    // Program should run.

    std::function<ebpf_result_t(void*, uint32_t*)> invoke =
        [&hook](_Inout_ void* context, _Out_ uint32_t* result) -> ebpf_result_t { return hook.fire(context, result); };

    // Test multiple subscriptions to the same perf buffer, to ensure that the perf buffer map will continue
    // to provide notifications to the subscriber.
    for (int i = 0; i < 3; i++) {
        perf_buffer_api_test_helper(
            test_map_fd,
            fake_app_ids,
            [&](int i) {
                std::vector<char> fake_app_id = fake_app_ids[i];
                fake_app_id.push_back('\0');
                std::string app_id = fake_app_id.data();
                uint32_t invoke_result = MAXUINT32;
                ctx->data_start = (uint8_t*)app_id.c_str();
                ctx->data_end = (uint8_t*)(app_id.c_str()) + app_id.size();
                REQUIRE(invoke(reinterpret_cast<void*>(ctx), &invoke_result) == EBPF_SUCCESS);
                REQUIRE(invoke_result == 0);
            },
            true);
    }

    hook.detach_and_close_link(&link);
    bpf_object__close(unique_test_sample_ebpf_object.release());
}

DECLARE_ALL_TEST_CASES("test-sample-perfbuffer", "[end_to_end]", test_sample_perf_buffer_test);
DECLARE_ALL_TEST_CASES("bindmonitor-perfbuffer", "[end_to_end]", bindmonitor_perf_buffer_test);
DECLARE_ALL_TEST_CASES("negative_perf_buffer_test", "[end_to_end]", negative_perf_buffer_test);

TEST_CASE("signature_checking", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    _ebpf_platform_code_integrity_test_signing_enabled = false;
    test_helper.initialize();
    _ebpf_platform_code_integrity_test_signing_enabled = true;

    const char* eku_list[] = {
        EBPF_CODE_SIGNING_EKU,
        EBPF_WINDOWS_COMPONENT_EKU,
    };
    // Thumbprint for "Microsoft Flighting Root 2014" certificate.
    const char* test_signed_root_certificate_thumbprint = "f8db7e1c16f1ffd4aaad4aad8dff0f2445184aeb";
    // Thumbprint for "Microsoft Root Certificate Authority 2010" certificate.
    const char* production_signed_root_certificate_thumbprint = "3b1efd3a66ea28b16697394703a72ca340a05bd5";
    const char* issuer = "US, Washington, Redmond, Microsoft Corporation, Microsoft Windows";

    std::wstring test_file = L"%windir%\\system32\\drivers\\tcpip.sys";

    // Expand environment variables in the file name.
    wchar_t expanded_path[MAX_PATH];
    REQUIRE(ExpandEnvironmentStringsW(test_file.c_str(), expanded_path, MAX_PATH) > 0);

    ebpf_result result = ebpf_verify_sys_file_signature(
        expanded_path, issuer, production_signed_root_certificate_thumbprint, 0, eku_list);
    if (result != EBPF_SUCCESS) {
        result =
            ebpf_verify_sys_file_signature(expanded_path, issuer, test_signed_root_certificate_thumbprint, 0, eku_list);
    }
    REQUIRE(result == EBPF_SUCCESS);
}

TEST_CASE("signature_checking_negative", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    _ebpf_platform_code_integrity_test_signing_enabled = false;
    test_helper.initialize();
    _ebpf_platform_code_integrity_test_signing_enabled = true;

    const char* eku_list[] = {
        EBPF_CODE_SIGNING_EKU,
        EBPF_VERIFICATION_EKU,
    };
    const char* subject = EBPF_REQUIRED_SUBJECT;
    const char* root_thumbprint = EBPF_REQUIRED_ROOT_CERTIFICATE_THUMBPRINT;

    std::wstring test_file = L"%windir%\\system32\\drivers\\tcpip.sys";

    // Expand environment variables in the file name.
    wchar_t expanded_path[MAX_PATH];
    REQUIRE(ExpandEnvironmentStringsW(test_file.c_str(), expanded_path, MAX_PATH) > 0);

    REQUIRE(ebpf_verify_sys_file_signature(expanded_path, subject, root_thumbprint, 0, eku_list) != EBPF_SUCCESS);
}

/**
 * @brief This test validates a pattern of synchronized updates to a map. There are two maps:
 * map_1 and map_2. map_1 is a hash map that points to a value in map_2, creating a dependency between the two maps.
 * Removing entries from map_2 requires that all programs that may be using the old value in map_1
 * have completed before the entry in map_2 can be safely removed, which is ensured by the ebpf_program_synchronize API.
 *
 * @param[in] execution_type The execution type for the eBPF program (JIT, Interpreter, or Native).
 */
static void
test_map_synchronized_update(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "map_synchronized_update_um.dll" : "map_synchronized_update.o");

    // Load eBPF program.
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    fd_t map_1_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "map_1");
    REQUIRE(map_1_fd > 0);

    fd_t map_2_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "map_2");
    REQUIRE(map_2_fd > 0);

    fd_t failure_stats_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "failure_stats");
    REQUIRE(failure_stats_fd > 0);

    // Initialize the maps.
    uint32_t zero_key = 0;
    uint32_t value_1 = 0;
    uint32_t value_2 = 1;

    // Insert the initial values into the maps.
    REQUIRE(bpf_map_update_elem(map_1_fd, &zero_key, &value_1, 0) == 0);
    REQUIRE(bpf_map_update_elem(map_2_fd, &value_1, &value_2, 0) == 0);

    int bpf_prog_test_run_opt_return_value = 0;
    std::jthread prog_test_run_thread([&]() {
        bpf_test_run_opts opts = {};
        sample_program_context_t ctx = {};
        opts.batch_size = 64;
        opts.repeat = 1000000;
        opts.ctx_in = &ctx;
        opts.ctx_size_in = sizeof(sample_program_context_t);
        opts.ctx_out = &ctx;
        opts.ctx_size_out = sizeof(sample_program_context_t);
        bpf_prog_test_run_opt_return_value = bpf_prog_test_run_opts(program_fd, &opts);
    });

    // Replace entry in map_2 with a new value.
    for (uint32_t i = 0; i < 10000; i++) {
        uint32_t old_value1 = i;
        uint32_t new_value_1 = i + 1;
        uint32_t new_value_2 = i + 2;

        // Insert the new values into map_2.
        REQUIRE(bpf_map_update_elem(map_2_fd, &new_value_1, &new_value_2, 0) == 0);

        // Update the value in map_1 to point to the new value.
        REQUIRE(bpf_map_update_elem(map_1_fd, &zero_key, &new_value_1, 0) == 0);

        // Wait for any already executing programs to finish.
        REQUIRE(ebpf_program_synchronize() == EBPF_SUCCESS);

        // Remove the old value from map_2.
        // If any programs are still running on the old value, this will increment the failure stats counter.
        REQUIRE(bpf_map_delete_elem(map_2_fd, &old_value1) == 0);
    }

    prog_test_run_thread.join();

    // Check the failure stats.
    uint32_t failure_count = 0;
    REQUIRE(bpf_map_lookup_elem(failure_stats_fd, &zero_key, &failure_count) == 0);
    REQUIRE(failure_count == 0);

    bpf_object__close(unique_object.release());
}

DECLARE_ALL_TEST_CASES("test_map_synchronized_update", "[end_to_end]", test_map_synchronized_update);

/**
 * @brief This function tests that reference from outer map to inner map is maintained
 * even when the inner map FD is closed. Also, when the outer map FD id closed, the inner
 * map reference is released.
 *
 * @param map_type The type of the outer map.
 */
void
_test_nested_maps_user_reference(bpf_map_type map_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    const int num_inner_maps = 5;
    fd_t inner_map_fds[num_inner_maps];
    uint32_t map_id = 0;

    for (int i = 0; i < num_inner_maps; ++i) {
        std::string name = "inner_map" + std::to_string(i + 1);
        inner_map_fds[i] =
            bpf_map_create(BPF_MAP_TYPE_ARRAY, name.c_str(), sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
        REQUIRE(inner_map_fds[i] > 0);
    }

    // Create outer map with the inner map handle in options.
    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fds[0]};
    fd_t outer_map_fd =
        bpf_map_create(map_type, "outer_map", sizeof(uint32_t), sizeof(fd_t), 2 * num_inner_maps, &opts);
    REQUIRE(outer_map_fd > 0);

    // Close outer map FD so that it is deleted. Validates that empty outer map is deleted.
    Platform::_close(outer_map_fd);

    // Create outer map again with the inner map handle in options.
    opts = {.inner_map_fd = (uint32_t)inner_map_fds[0]};
    outer_map_fd = bpf_map_create(map_type, "outer_map", sizeof(uint32_t), sizeof(fd_t), 2 * num_inner_maps, &opts);
    REQUIRE(outer_map_fd > 0);

    // Insert all inner maps in outer map.
    for (int i = 0; i < num_inner_maps; ++i) {
        uint32_t key = i;
        uint32_t result = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fds[i], 0);
        REQUIRE(result == ERROR_SUCCESS);
    }

    // For each inner map, add a value to it.
    for (int i = 0; i < num_inner_maps; ++i) {
        uint32_t key = 0;
        uint32_t value = 100 + i;
        uint32_t result = bpf_map_update_elem(inner_map_fds[i], &key, &value, 0);
        REQUIRE(result == ERROR_SUCCESS);
    }

    // Close FDs for the inner maps. The maps should still exist and can be queried from the outer map.
    for (int i = 0; i < num_inner_maps; ++i) {
        Platform::_close(inner_map_fds[i]);
    }

    // For each inner map, get the inner map ID from outer map and query the value from it.
    for (int i = 0; i < num_inner_maps; ++i) {
        uint32_t key = i;
        uint32_t inner_map_id = 0;
        uint32_t result = bpf_map_lookup_elem(outer_map_fd, &key, &inner_map_id);
        REQUIRE(result == 0);
        REQUIRE(inner_map_id > 0);
        fd_t inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
        REQUIRE(inner_map_fd > 0);
        // Query value from inner_map
        key = 0;
        uint32_t value = 0;
        result = bpf_map_lookup_elem(inner_map_fd, &key, &value);
        REQUIRE(result == ERROR_SUCCESS);
        REQUIRE(value == static_cast<uint32_t>(100 + i));
        Platform::_close(inner_map_fd);
    }

    Platform::_close(outer_map_fd);

    // Now all the maps should be closed.
    REQUIRE(bpf_map_get_next_id(0, &map_id) < 0);
}

TEST_CASE("array_map_of_maps_user_reference", "[libbpf]")
{
    _test_nested_maps_user_reference(BPF_MAP_TYPE_ARRAY_OF_MAPS);
}
TEST_CASE("hash_map_of_maps_user_reference", "[libbpf]")
{
    _test_nested_maps_user_reference(BPF_MAP_TYPE_HASH_OF_MAPS);
}

/**
 * @brief This function tests that reference from prog array map to programs is maintained
 * even when the program FD is closed. Also, when the outer map FD is closed, the program
 * references are also released.
 *
 * @param execution_type The type of execution for the eBPF programs.
 */
void
_test_prog_array_map_user_reference(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;

    program_info_provider_t bind_program_info;
    REQUIRE(bind_program_info.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_tailcall_um.dll" : "bindmonitor_tailcall.o");
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    // Create a new prog_array_map with 3 entries.
    fd_t prog_array_map_fd =
        bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, "prog_array_map", sizeof(uint32_t), sizeof(fd_t), 3, nullptr);
    REQUIRE(prog_array_map_fd > 0);

    // Get FDs for the three programs.
    fd_t program0_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "BindMonitor"));
    REQUIRE(program0_fd > 0);

    fd_t program1_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee0"));
    REQUIRE(program1_fd > 0);

    fd_t program2_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee1"));
    REQUIRE(program2_fd > 0);

    // Insert the program FDs into the prog_array_map.
    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_array_map_fd, &index, &program0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_array_map_fd, &index, &program1_fd, 0) == 0);
    index = 2;
    REQUIRE(bpf_map_update_elem(prog_array_map_fd, &index, &program2_fd, 0) == 0);

    // Close the program FDs. The programs should still exist and can be queried from the prog_array_map.
    bpf_object__close(unique_object.release());

    // Create an array of program FDs and get the program FDs from the prog_array_map in a loop.
    fd_t program_fds[3];
    for (uint32_t i = 0; i < 3; i++) {
        uint32_t program_id = 0;
        result = bpf_map_lookup_elem(prog_array_map_fd, &i, &program_id);

        REQUIRE(result == 0);
        REQUIRE(program_id > 0);
        program_fds[i] = bpf_prog_get_fd_by_id(program_id);
        REQUIRE(program_fds[i] > 0);
    }

    // Query object info for each program.
    for (uint32_t i = 0; i < 3; i++) {
        bpf_prog_info program_info = {};
        uint32_t program_info_size = sizeof(program_info);
        REQUIRE(bpf_obj_get_info_by_fd(program_fds[i], &program_info, &program_info_size) == 0);
    }

    // Close the program FDs, followed by the prog_array_map FD.
    for (uint32_t i = 0; i < 3; i++) {
        Platform::_close(program_fds[i]);
    }
    Platform::_close(prog_array_map_fd);

    // All programs and maps should be closed now.
    uint32_t start_id = 0;
    REQUIRE(bpf_map_get_next_id(0, &start_id) < 0);
    REQUIRE(bpf_prog_get_next_id(0, &start_id) < 0);
}

DECLARE_JIT_TEST_CASES(
    "prog_array_map_user_reference", "[end_to_end][user_reference]", _test_prog_array_map_user_reference);

// This test validates extensible map user APIs.
void
_test_extensible_maps_user_apis(ebpf_map_type_t map_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    uint32_t map_size = 10;

    REQUIRE((map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP || map_type == BPF_MAP_TYPE_SAMPLE_HASH_MAP));

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;

    {
        // Try to create extensible map without initializing the map provider.
        // This should fail.
        fd_t invalid_map_fd =
            bpf_map_create(map_type, "invalid_map", sizeof(uint32_t), sizeof(uint32_t), map_size, nullptr);
        REQUIRE(invalid_map_fd < 0);
    }

    // Create a map with invalid map types. This should fail.
    fd_t invalid_map_fd =
        bpf_map_create(BPF_MAP_TYPE_MAX, "invalid_map", sizeof(uint32_t), sizeof(uint32_t), map_size, nullptr);
    REQUIRE(invalid_map_fd < 0);

    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    test_sample_map_provider_t sample_map_provider;
    REQUIRE(sample_map_provider.initialize(map_type) == EBPF_SUCCESS);

    fd_t extensible_map_fd =
        bpf_map_create(map_type, "extensible_map", sizeof(uint32_t), sizeof(uint32_t), map_size, nullptr);
    REQUIRE(extensible_map_fd > 0);

    auto require_and_close = [](bool condition, fd_t fd) {
        if (condition == false) {
            Platform::_close(fd);
        }
        REQUIRE(condition);
    };

    // Add entries up to the map size.
    for (uint32_t i = 0; i < map_size; i++) {
        uint32_t key = i;
        uint32_t value = i + 100;
        int result = bpf_map_update_elem(extensible_map_fd, &key, &value, 0);
        require_and_close((result == 0), extensible_map_fd);
    }
    // Try updating an element beyond the current map size.
    {
        uint32_t key = map_size + 10;
        uint32_t value = 999;
        int result = bpf_map_update_elem(extensible_map_fd, &key, &value, 0);
        require_and_close((result != 0), extensible_map_fd);
    }

    // Lookup elements and validate values.
    for (uint32_t i = 0; i < map_size; i++) {
        uint32_t key = i;
        uint32_t value = 0;
        int result = bpf_map_lookup_elem(extensible_map_fd, &key, &value);
        require_and_close((result == 0), extensible_map_fd);
        require_and_close((value == i + 100), extensible_map_fd);
    }
    // Lookup an invalid key
    {
        uint32_t key = map_size + 20;
        uint32_t value = 0;
        int result = bpf_map_lookup_elem(extensible_map_fd, &key, &value);
        require_and_close((result != 0), extensible_map_fd);
    }

    // Delete all elements.
    for (uint32_t i = 0; i < map_size; i++) {
        uint32_t key = i;
        int result = bpf_map_delete_elem(extensible_map_fd, &key);
        require_and_close((result == 0), extensible_map_fd);
    }

    // Validate deleted elements are no longer present.
    for (uint32_t i = 0; i < map_size; i++) {
        uint32_t key = i;
        uint32_t value = 0;
        int result = bpf_map_lookup_elem(extensible_map_fd, &key, &value);
        if (map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
            // For array maps, lookup succeeds but value is zero after deletion
            require_and_close((result == 0), extensible_map_fd);
            require_and_close((value == 0), extensible_map_fd);
        } else {
            // For hash maps, lookup fails after deletion
            require_and_close((result != 0), extensible_map_fd);
        }
    }

    // Re-insert the elements.
    for (uint32_t i = 0; i < map_size; i++) {
        uint32_t key = i;
        uint32_t value = i + 100;
        int result = bpf_map_update_elem(extensible_map_fd, &key, &value, 0);
        require_and_close((result == 0), extensible_map_fd);
    }

    // Test bpf_map_get_next_key on extensible map.
    uint32_t next_key = 0;
    uint32_t count = 0;
    uint32_t* prev_key = nullptr;

    // First call with nullptr should return key 0.
    int result = bpf_map_get_next_key(extensible_map_fd, nullptr, &next_key);
    require_and_close((result == 0), extensible_map_fd);
    require_and_close((next_key == 0), extensible_map_fd);

    // Iterate through all keys in the map.
    prev_key = nullptr;
    count = 0;
    while (bpf_map_get_next_key(extensible_map_fd, prev_key, &next_key) == 0) {
        require_and_close((next_key == count), extensible_map_fd);
        count++;
        prev_key = &next_key;
    }
    // Should have iterated through all map_size entries.
    require_and_close((count == map_size), extensible_map_fd);

    // Test bpf_map_update_batch on extensible map.
    {
        // Clear the map first for batch testing.
        for (uint32_t i = 0; i < map_size; i++) {
            uint32_t key = i;
            result = bpf_map_delete_elem(extensible_map_fd, &key);
            require_and_close((result == 0), extensible_map_fd);
        }

        // Prepare batch data.
        std::vector<uint32_t> batch_keys(map_size);
        std::vector<uint32_t> batch_values(map_size);
        for (uint32_t i = 0; i < map_size; i++) {
            batch_keys[i] = i;
            batch_values[i] = i + 500; // Different values to distinguish from previous tests
        }

        // Test batch update.
        bpf_map_batch_opts opts = {};
        uint32_t batch_count = map_size;
        result = bpf_map_update_batch(extensible_map_fd, batch_keys.data(), batch_values.data(), &batch_count, &opts);
        require_and_close((result == 0), extensible_map_fd);
        require_and_close((batch_count == map_size), extensible_map_fd);

        // Validate batch updated values.
        for (uint32_t i = 0; i < map_size; i++) {
            uint32_t key = i;
            uint32_t value = 0;
            result = bpf_map_lookup_elem(extensible_map_fd, &key, &value);
            require_and_close((result == 0), extensible_map_fd);
            require_and_close((value == i + 500), extensible_map_fd);
        }

        // Test batch update with BPF_NOEXIST flag on existing keys (should fail).
        opts.elem_flags = BPF_NOEXIST;
        batch_count = map_size;
        for (uint32_t i = 0; i < map_size; i++) {
            batch_values[i] = i + 600; // New values
        }
        result = bpf_map_update_batch(extensible_map_fd, batch_keys.data(), batch_values.data(), &batch_count, &opts);
        require_and_close((result != 0), extensible_map_fd); // Should fail due to existing keys

        // Test batch update with BPF_EXIST flag on existing keys (should succeed).
        opts.elem_flags = BPF_EXIST;
        batch_count = map_size;
        result = bpf_map_update_batch(extensible_map_fd, batch_keys.data(), batch_values.data(), &batch_count, &opts);
        require_and_close((result == 0), extensible_map_fd);
        require_and_close((batch_count == map_size), extensible_map_fd);

        // Validate updated values.
        for (uint32_t i = 0; i < map_size; i++) {
            uint32_t key = i;
            uint32_t value = 0;
            result = bpf_map_lookup_elem(extensible_map_fd, &key, &value);
            require_and_close((result == 0), extensible_map_fd);
            require_and_close((value == i + 600), extensible_map_fd);
        }
    }

    // Test bpf_map_delete_batch on extensible map.
    {
        // Prepare data for delete batch test (map should still have data from previous test).
        std::vector<uint32_t> delete_keys(map_size / 2); // Delete half the entries
        for (uint32_t i = 0; i < map_size / 2; i++) {
            delete_keys[i] = i;
        }

        // Test batch delete.
        bpf_map_batch_opts delete_opts = {};
        uint32_t delete_count = map_size / 2;
        result = bpf_map_delete_batch(extensible_map_fd, delete_keys.data(), &delete_count, &delete_opts);
        require_and_close((result == 0), extensible_map_fd);
        require_and_close((delete_count == map_size / 2), extensible_map_fd);

        // Validate that deleted keys are no longer present, but remaining keys still exist.
        for (uint32_t i = 0; i < map_size; i++) {
            uint32_t key = i;
            uint32_t value = 0;
            result = bpf_map_lookup_elem(extensible_map_fd, &key, &value);
            if (i < map_size / 2) {
                if (map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
                    // For array maps, lookup succeeds but value is zero after deletion
                    require_and_close((result == 0), extensible_map_fd);
                    require_and_close((value == 0), extensible_map_fd);
                } else {
                    // For hash maps, lookup fails after deletion
                    require_and_close((result != 0), extensible_map_fd);
                }
            } else {
                // Remaining keys should still exist with their values
                require_and_close((result == 0), extensible_map_fd);
                require_and_close((value == i + 600), extensible_map_fd);
            }
        }
    }

    // Test bpf_map_lookup_and_delete_batch on extensible map.
    {
        // Re-populate the map with fresh data for lookup_and_delete test.
        for (uint32_t i = 0; i < map_size; i++) {
            uint32_t key = i;
            uint32_t value = i + 700; // New values to distinguish from previous tests
            result = bpf_map_update_elem(extensible_map_fd, &key, &value, 0);
            require_and_close((result == 0), extensible_map_fd);
        }

        // Prepare data for lookup and delete batch.
        std::vector<uint32_t> lookup_delete_keys(map_size);
        std::vector<uint32_t> lookup_delete_values(map_size);
        void* in_batch = nullptr;  // Start from beginning
        void* out_batch = nullptr; // Not used for iteration

        // Test batch lookup and delete.
        bpf_map_batch_opts lookup_delete_opts = {};
        uint32_t lookup_delete_count = map_size;
        result = bpf_map_lookup_and_delete_batch(
            extensible_map_fd,
            in_batch,
            out_batch,
            lookup_delete_keys.data(),
            lookup_delete_values.data(),
            &lookup_delete_count,
            &lookup_delete_opts);

        // bpf_map_lookup_and_delete_batch is not supported on extensible maps.
        // This should fail with EBPF_NOT_SUPPORTED.
        require_and_close((result != 0), extensible_map_fd);
    }

    // Clean up
    Platform::_close(extensible_map_fd);
}

TEST_CASE("extensible_maps_user_apis", "[extensible_maps]")
{
    _test_extensible_maps_user_apis(BPF_MAP_TYPE_SAMPLE_ARRAY_MAP);
    _test_extensible_maps_user_apis(BPF_MAP_TYPE_SAMPLE_HASH_MAP);
}

TEST_CASE("extensible_maps_user_apis_negative", "[extensible_maps]")
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    ebpf_result result;

    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    test_sample_map_provider_t sample_map_provider;
    REQUIRE(sample_map_provider.initialize(BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) == EBPF_SUCCESS);

    // 1. create an extensible map.
    fd_t extensible_map_fd = bpf_map_create(
        BPF_MAP_TYPE_SAMPLE_ARRAY_MAP, "extensible_map", sizeof(uint32_t), sizeof(uint32_t), 10, nullptr);
    REQUIRE(extensible_map_fd > 0);

    // 2. Invoke test_ioctl_map_write for the map. This should fail.
    ebpf_handle_t map_handle = (ebpf_handle_t)Platform::_get_osfhandle(extensible_map_fd);
    uint32_t data = 42;
    REQUIRE(test_ioctl_map_write(map_handle, &data, sizeof(data)) != EBPF_SUCCESS);

    // Test ebpf_map_set_wait_handle API. This should fail.
    {
        // Create wait handle for notifications.
        HANDLE wait_handle = CreateEvent(nullptr, false, false, nullptr);
        REQUIRE(wait_handle != NULL);

        // Set map wait handle. This should fail.
        result = ebpf_map_set_wait_handle(extensible_map_fd, 0, (ebpf_handle_t)wait_handle);
        REQUIRE(result != EBPF_SUCCESS);

        CloseHandle(wait_handle);
    }

    // Test ebpf_map_update_element_with_handle API. This should fail for extensible maps.
    {
        // Create a new array map.
        fd_t array_map_fd =
            bpf_map_create(BPF_MAP_TYPE_ARRAY, "test_array", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
        REQUIRE(array_map_fd > 0);

        // Get the handle from the array map fd.
        ebpf_handle_t array_map_handle = (ebpf_handle_t)Platform::_get_osfhandle(array_map_fd);

        // Try to update the extensible map with the array map handle. This should fail.
        uint32_t key = 0;
        REQUIRE(
            test_ioctl_map_update_element_with_handle(map_handle, sizeof(key), (uint8_t*)&key, array_map_handle) !=
            EBPF_SUCCESS);

        Platform::_close(array_map_fd);
    }

    Platform::_close(extensible_map_fd);
}

void
_test_extensible_maps_program_load_common(ebpf_map_type_t type, ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    bpf_object_ptr unique_object;
    int result;
    const char* error_message = nullptr;
    fd_t program_fd;
    bpf_link_ptr link;
    int iteration = 10;

    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE) ? "extensible_map_basic_um.dll" : "extensible_map_basic.o";

    // Try to load the program without initializing the map provider. This should fail.
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);
    REQUIRE(result != 0);

    // Initialize providers for both the map types, as the BPF program has both the map types.
    test_sample_map_provider_t sample_array_map_provider;
    test_sample_map_provider_t sample_hash_map_provider;
    REQUIRE(sample_array_map_provider.initialize(BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) == EBPF_SUCCESS);
    REQUIRE(sample_hash_map_provider.initialize(BPF_MAP_TYPE_SAMPLE_HASH_MAP) == EBPF_SUCCESS);

    auto require_and_close_object = [&](bool condition) {
        if (!condition) {
            bpf_object__close(unique_object.release());
        }
        REQUIRE(condition);
    };

    // Load eBPF program.
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);
    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    const char* map_name = (type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) ? "sample_array_map" : "sample_hash_map";
    fd_t result_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "result_map");
    require_and_close_object(result_map_fd > 0);

    fd_t sample_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), map_name);
    require_and_close_object(sample_map_fd > 0);

    auto validate_result_map = [&](uint32_t expected_value) {
        uint32_t key = 0;
        uint32_t result_value = 0;
        require_and_close_object(bpf_map_lookup_elem(result_map_fd, &key, &result_value) == 0);
        require_and_close_object(result_value == expected_value);
    };

    auto validate_sample_map_value = [&](uint32_t expected_value, bool expect_lookup_to_fail = false) {
        uint32_t key = 0;
        uint32_t map_value = 0;
        if (expect_lookup_to_fail) {
            require_and_close_object(bpf_map_lookup_elem(sample_map_fd, &key, &map_value) != 0);
            return;
        } else {
            require_and_close_object(bpf_map_lookup_elem(sample_map_fd, &key, &map_value) == 0);
            require_and_close_object(map_value == expected_value);
        }
    };

    // Set config map.
    fd_t config_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "config_map");
    require_and_close_object(config_map_fd > 0);
    uint32_t config_key = 0;
    uint32_t config_value = type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP ? 1 : 2;
    require_and_close_object((bpf_map_update_elem(config_map_fd, &config_key, &config_value, 0) == 0));

    // Set initial value in the map.
    uint32_t key = 0;
    uint32_t value = 1234;
    require_and_close_object((bpf_map_update_elem(sample_map_fd, &key, &value, 0) == 0));

    // First invoke "test_map_read_increment" program. The map value should be incremented by 1 by the program for each
    // iteration.
    bpf_test_run_opts opts = {};
    sample_program_context_t ctx = {};
    opts.batch_size = 1;
    opts.repeat = iteration;
    opts.ctx_in = &ctx;
    opts.ctx_size_in = sizeof(sample_program_context_t);
    opts.ctx_out = &ctx;
    opts.ctx_size_out = sizeof(sample_program_context_t);

    program_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_read_increment"));
    require_and_close_object(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    require_and_close_object(result == 0);

    // Lookup the sample map value and validate it is updated.
    validate_sample_map_value(value + iteration);
    validate_result_map(1);
    value += iteration;

    // Now invoke "test_map_read_helper_increment" program. The map value should be incremented by 1 by the program for
    // each iteration.
    program_fd =
        bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_read_helper_increment"));
    require_and_close_object(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    require_and_close_object(result == 0);

    // Lookup the sample map value and validate it is updated.
    validate_sample_map_value(value + iteration);
    validate_result_map(1);
    value += iteration;

    // Set iteration to 1 for the remaining tests.
    opts.repeat = 1;

    // Now invoke "test_map_read_helper_increment_invalid" program. Map lookup should fail in this case.
    program_fd = bpf_program__fd(
        bpf_object__find_program_by_name(unique_object.get(), "test_map_read_helper_increment_invalid"));
    require_and_close_object(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    require_and_close_object(result == 0);

    // Validate that the program failed by checking the result map.
    validate_result_map(0);

    // Now invoke "test_map_update_element" program. The value should be set to 42.
    program_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_update_element"));
    require_and_close_object(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    require_and_close_object(result == 0);

    // Lookup the sample map value and validate it is set to 42.
    validate_sample_map_value(42);
    validate_result_map(1);

    // Now invoke "test_map_delete_element" program. The value should be deleted and set to 0.
    program_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_delete_element"));
    require_and_close_object(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    require_and_close_object(result == 0);

    // Lookup the sample map value and validate it is set to 0.
    if (type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
        validate_sample_map_value(0);
    } else {
        validate_sample_map_value(0, true);
    }
    validate_result_map(1);

    // Set map value to 200.
    value = 200;
    require_and_close_object((bpf_map_update_elem(sample_map_fd, &key, &value, 0) == 0));

    // Invoke "test_map_find_and_delete_element" program.
    program_fd =
        bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_find_and_delete_element"));
    require_and_close_object(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    require_and_close_object(result == 0);

    if (type == BPF_MAP_TYPE_SAMPLE_HASH_MAP) {
        // find_and_delete is supported for hash maps, validate that the value is deleted.
        validate_sample_map_value(0, true);
        validate_result_map(1);
    } else {
        // find_and_delete is not supported for array maps, so value should remain unchanged.
        validate_sample_map_value(200);
        validate_result_map(0);
    }

    // Invoke "test_map_push_elem" program.
    program_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_push_elem"));
    require_and_close_object(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    require_and_close_object(result == 0);

    // push_elem is not supported for array or hash maps, validate that the call failed.
    validate_result_map(0);

    // Invoke "test_map_pop_elem" program.
    program_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_pop_elem"));
    require_and_close_object(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    require_and_close_object(result == 0);

    // pop_elem is not supported for array or hash maps, validate that the call failed.
    validate_result_map(0);

    // Invoke "test_map_peek_elem" program.
    program_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_peek_elem"));
    require_and_close_object(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    require_and_close_object(result == 0);

    // peek_elem is not supported for array or hash maps, validate that the call failed.
    validate_result_map(0);

    bpf_object__close(unique_object.release());
}

void
_test_extensible_maps_program_load(ebpf_execution_type_t execution_type)
{
    _test_extensible_maps_program_load_common(BPF_MAP_TYPE_SAMPLE_ARRAY_MAP, execution_type);
    _test_extensible_maps_program_load_common(BPF_MAP_TYPE_SAMPLE_HASH_MAP, execution_type);
}

DECLARE_ALL_TEST_CASES(
    "extensible_maps_program_load", "[end_to_end][extensible_maps]", _test_extensible_maps_program_load);

static void
_test_extensible_maps_invalid(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    test_helper.initialize();
    bpf_object_ptr unique_object;
    int result;
    const char* error_message = nullptr;
    fd_t program_fd;

    program_info_provider_t sock_addr_program_info;
    REQUIRE(sock_addr_program_info.initialize(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR) == EBPF_SUCCESS);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE) ? "extensible_map_invalid_um.dll" : "extensible_map_invalid.o";

    test_sample_map_provider_t sample_map_provider;
    REQUIRE(sample_map_provider.initialize(BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) == EBPF_SUCCESS);

    // Try to load the program with invalid extensible map usage.
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);
    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result != 0);

    bpf_object__close(unique_object.release());
}

DECLARE_ALL_TEST_CASES(
    "extensible_maps_invalid", "[end_to_end][extensible_maps][!mayfail]", _test_extensible_maps_invalid);
