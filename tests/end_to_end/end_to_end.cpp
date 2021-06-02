// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <mutex>
#include <thread>
#include <WinSock2.h>

#include "catch2\catch.hpp"
#include "common_tests.h"
#include "ebpf_api.h"
#include "ebpf_bind_program_data.h"
#include "ebpf_core.h"
#include "ebpf_xdp_program_data.h"
#include "helpers.h"
#include "mock.h"
#include "tlv.h"
namespace ebpf {
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#include "../sample/ebpf.h"
#pragma warning(pop)
}; // namespace ebpf

ebpf_handle_t
GlueCreateFileW(
    PCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    PSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    ebpf_handle_t hTemplateFile)
{
    UNREFERENCED_PARAMETER(lpFileName);
    UNREFERENCED_PARAMETER(dwDesiredAccess);
    UNREFERENCED_PARAMETER(dwShareMode);
    UNREFERENCED_PARAMETER(lpSecurityAttributes);
    UNREFERENCED_PARAMETER(dwCreationDisposition);
    UNREFERENCED_PARAMETER(dwFlagsAndAttributes);
    UNREFERENCED_PARAMETER(hTemplateFile);

    return (ebpf_handle_t)0x12345678;
}

BOOL
GlueCloseHandle(ebpf_handle_t hObject)
{
    UNREFERENCED_PARAMETER(hObject);
    return TRUE;
}

BOOL
GlueDeviceIoControl(
    ebpf_handle_t hDevice,
    DWORD dwIoControlCode,
    PVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    PDWORD lpBytesReturned,
    OVERLAPPED* lpOverlapped)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(nInBufferSize);
    UNREFERENCED_PARAMETER(dwIoControlCode);
    UNREFERENCED_PARAMETER(lpOverlapped);

    ebpf_result_t result;
    const ebpf_operation_header_t* user_request = reinterpret_cast<decltype(user_request)>(lpInBuffer);
    ebpf_operation_header_t* user_reply = nullptr;
    *lpBytesReturned = 0;
    auto request_id = user_request->id;
    size_t minimum_request_size = 0;
    size_t minimum_reply_size = 0;

    result = ebpf_core_get_protocol_handler_properties(request_id, &minimum_request_size, &minimum_reply_size);
    if (result != EBPF_SUCCESS)
        goto Fail;

    if (user_request->length < minimum_request_size) {
        result = EBPF_INVALID_ARGUMENT;
        goto Fail;
    }

    if (minimum_reply_size > 0) {
        user_reply = reinterpret_cast<decltype(user_reply)>(lpOutBuffer);
        if (!user_reply) {
            result = EBPF_INVALID_ARGUMENT;
            goto Fail;
        }
        if (nOutBufferSize < minimum_reply_size) {
            result = EBPF_INVALID_ARGUMENT;
            goto Fail;
        }
        user_reply->length = static_cast<uint16_t>(nOutBufferSize);
        user_reply->id = user_request->id;
        *lpBytesReturned = user_reply->length;
    }

    result =
        ebpf_core_invoke_protocol_handler(request_id, user_request, user_reply, static_cast<uint16_t>(nOutBufferSize));

    if (result != EBPF_SUCCESS)
        goto Fail;

    return TRUE;

Fail:
    if (result != EBPF_SUCCESS) {
        switch (result) {
        case EBPF_NO_MEMORY:
            SetLastError(ERROR_OUTOFMEMORY);
            break;
        case EBPF_KEY_NOT_FOUND:
            SetLastError(ERROR_NOT_FOUND);
            break;
        case EBPF_INVALID_ARGUMENT:
            SetLastError(ERROR_INVALID_PARAMETER);
            break;
        case EBPF_NO_MORE_KEYS:
            SetLastError(ERROR_NO_MORE_ITEMS);
            break;
        case EBPF_INSUFFICIENT_BUFFER:
            SetLastError(ERROR_MORE_DATA);
            break;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            break;
        }
    }

    return FALSE;
}

std::vector<uint8_t>
prepare_udp_packet(uint16_t udp_length)
{
    std::vector<uint8_t> packet(sizeof(ebpf::IPV4_HEADER) + sizeof(ebpf::UDP_HEADER));
    auto ipv4 = reinterpret_cast<ebpf::IPV4_HEADER*>(packet.data());
    auto udp = reinterpret_cast<ebpf::UDP_HEADER*>(ipv4 + 1);

    ipv4->Protocol = 17;

    udp->length = udp_length;

    return packet;
}

class _test_helper
{
  public:
    _test_helper()
    {
        device_io_control_handler = GlueDeviceIoControl;
        create_file_handler = GlueCreateFileW;
        close_handle_handler = GlueCloseHandle;
        REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
        ec_initialized = true;
        REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);
        api_initialized = true;
    }
    ~_test_helper()
    {
        if (api_initialized)
            ebpf_api_terminate();
        if (ec_initialized)
            ebpf_core_terminate();

        device_io_control_handler = nullptr;
        create_file_handler = nullptr;
        close_handle_handler = nullptr;
    }

  private:
    bool ec_initialized = false;
    bool api_initialized = false;
};

#define SAMPLE_PATH ""

TEST_CASE("droppacket-jit", "[droppacket_jit]")
{
    _test_helper test_helper;

    ebpf_handle_t program_handle;
    ebpf_handle_t map_handle;
    uint32_t count_of_map_handle = 1;
    uint32_t result = 0;
    const char* error_message = NULL;

    single_instance_hook_t hook;
    program_information_provider_t xdp_program_information(EBPF_PROGRAM_TYPE_XDP);

    REQUIRE(
        (result = ebpf_api_load_program(
             SAMPLE_PATH "droppacket.o",
             "xdp",
             EBPF_EXECUTION_JIT,
             &program_handle,
             &count_of_map_handle,
             &map_handle,
             &error_message),
         error_message ? printf("ebpf_api_load_program failed with %s\n", error_message) : 0,
         ebpf_api_free_string(error_message),
         error_message = nullptr,
         result == EBPF_SUCCESS));

    REQUIRE(hook.attach(program_handle) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0);

    uint32_t key = 0;
    uint64_t value = 1000;
    REQUIRE(
        ebpf_api_map_update_element(map_handle, sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
        EBPF_SUCCESS);

    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};

    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    REQUIRE(result == 2);

    REQUIRE(
        ebpf_api_map_find_element(map_handle, sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
        EBPF_SUCCESS);
    REQUIRE(value == 1001);

    REQUIRE(ebpf_api_map_delete_element(map_handle, sizeof(key), (uint8_t*)&key) == EBPF_SUCCESS);

    REQUIRE(
        ebpf_api_map_find_element(map_handle, sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
        EBPF_SUCCESS);
    REQUIRE(value == 0);

    packet = prepare_udp_packet(10);
    xdp_md_t ctx2{packet.data(), packet.data() + packet.size()};

    REQUIRE(hook.fire(&ctx2, &result) == EBPF_SUCCESS);
    REQUIRE(result == 1);

    REQUIRE(
        ebpf_api_map_find_element(map_handle, sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
        EBPF_SUCCESS);
    REQUIRE(value == 0);

    hook.detach();
}

TEST_CASE("droppacket-interpret", "[droppacket_interpret]")
{
    _test_helper test_helper;

    ebpf_handle_t program_handle;
    const char* error_message = NULL;
    ebpf_handle_t map_handle;
    uint32_t count_of_map_handle = 1;
    uint32_t result = 0;

    program_information_provider_t xdp_program_information(EBPF_PROGRAM_TYPE_XDP);

    single_instance_hook_t hook;

    REQUIRE(
        (result = ebpf_api_load_program(
             SAMPLE_PATH "droppacket.o",
             "xdp",
             EBPF_EXECUTION_INTERPRET,
             &program_handle,
             &count_of_map_handle,
             &map_handle,
             &error_message),
         error_message ? printf("ebpf_api_load_program failed with %s\n", error_message) : 0,
         ebpf_api_free_string(error_message),
         error_message = NULL,
         result == EBPF_SUCCESS));

    REQUIRE(hook.attach(program_handle) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0);

    uint32_t key = 0;
    uint64_t value = 1000;
    REQUIRE(
        ebpf_api_map_update_element((ebpf_handle_t)1, sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
        EBPF_SUCCESS);

    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    REQUIRE(result == 2);

    REQUIRE(
        ebpf_api_map_find_element((ebpf_handle_t)1, sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
        EBPF_SUCCESS);
    REQUIRE(value == 1001);

    REQUIRE(ebpf_api_map_delete_element((ebpf_handle_t)1, sizeof(key), (uint8_t*)&key) == EBPF_SUCCESS);

    REQUIRE(
        ebpf_api_map_find_element((ebpf_handle_t)1, sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
        EBPF_SUCCESS);
    REQUIRE(value == 0);

    packet = prepare_udp_packet(10);
    xdp_md_t ctx2{packet.data(), packet.data() + packet.size()};

    REQUIRE(hook.fire(&ctx2, &result) == EBPF_SUCCESS);
    REQUIRE(result == 1);

    REQUIRE(
        ebpf_api_map_find_element((ebpf_handle_t)1, sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
        EBPF_SUCCESS);
    REQUIRE(value == 0);
}

TEST_CASE("divide_by_zero_jit", "[divide_by_zero_jit]")
{
    _test_helper test_helper;

    ebpf_handle_t program_handle;
    ebpf_handle_t map_handle;
    uint32_t count_of_map_handle = 1;
    uint32_t result = 0;
    const char* error_message = NULL;

    single_instance_hook_t hook;
    program_information_provider_t xdp_program_information(EBPF_PROGRAM_TYPE_XDP);

    REQUIRE(
        (result = ebpf_api_load_program(
             SAMPLE_PATH "divide_by_zero.o",
             "xdp",
             EBPF_EXECUTION_JIT,
             &program_handle,
             &count_of_map_handle,
             &map_handle,
             &error_message),
         error_message ? printf("ebpf_api_load_program failed with %s\n", error_message) : 0,
         ebpf_api_free_string(error_message),
         error_message = nullptr,
         result == EBPF_SUCCESS));

    REQUIRE(hook.attach(program_handle) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0);

    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};

    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    REQUIRE(result == -1);

    hook.detach();
}

TEST_CASE("enum section", "[enum sections]")
{
    _test_helper test_helper;

    const char* error_message = nullptr;
    const tlv_type_length_value_t* section_data = nullptr;
    uint32_t result;

    REQUIRE(
        (result =
             ebpf_api_elf_enumerate_sections(SAMPLE_PATH "droppacket.o", nullptr, true, &section_data, &error_message),
         ebpf_api_free_string(error_message),
         error_message = nullptr,
         result == 0));
    for (auto current_section = tlv_child(section_data); current_section != tlv_next(section_data);
         current_section = tlv_next(current_section)) {
        auto section_name = tlv_child(current_section);
        auto type = tlv_next(section_name);
        auto map_count = tlv_next(type);
        auto program_bytes = tlv_next(map_count);
        auto stats_secton = tlv_next(program_bytes);

        REQUIRE(static_cast<tlv_type_t>(section_name->type) == tlv_type_t::STRING);
        REQUIRE(static_cast<tlv_type_t>(type->type) == tlv_type_t::STRING);
        REQUIRE(static_cast<tlv_type_t>(map_count->type) == tlv_type_t::UINT);
        REQUIRE(static_cast<tlv_type_t>(program_bytes->type) == tlv_type_t::BLOB);
        REQUIRE(static_cast<tlv_type_t>(stats_secton->type) == tlv_type_t::SEQUENCE);

        for (auto current_stat = tlv_child(stats_secton); current_stat != tlv_next(stats_secton);
             current_stat = tlv_next(current_stat)) {
            auto name = tlv_child(current_stat);
            auto value = tlv_next(name);
            REQUIRE(static_cast<tlv_type_t>(name->type) == tlv_type_t::STRING);
            REQUIRE(static_cast<tlv_type_t>(value->type) == tlv_type_t::UINT);
        }
    }
}

TEST_CASE("verify section", "[verify section]")
{
    _test_helper test_helper;

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;

    ebpf_api_verifier_stats_t stats;
    REQUIRE((
        result = ebpf_api_elf_verify_section(SAMPLE_PATH "droppacket.o", "xdp", false, &report, &error_message, &stats),
        ebpf_api_free_string(error_message),
        error_message = nullptr,
        result == 0));
    REQUIRE(report != nullptr);
    ebpf_api_free_string(report);
}

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
    uint64_t appid_length;
} process_entry_t;

uint32_t
get_bind_count_for_pid(ebpf_handle_t handle, uint64_t pid)
{
    process_entry_t entry{};
    ebpf_api_map_find_element(handle, sizeof(pid), (uint8_t*)&pid, sizeof(entry), (uint8_t*)&entry);

    return entry.count;
}

bind_action_t
emulate_bind(single_instance_hook_t& hook, uint64_t pid, const char* appid)
{
    uint32_t result;
    std::string app_id = appid;
    bind_md_t ctx{0};
    ctx.app_id_start = (uint8_t*)app_id.c_str();
    ctx.app_id_end = (uint8_t*)(app_id.c_str()) + app_id.size();
    ctx.process_id = pid;
    ctx.operation = BIND_OPERATION_BIND;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    return static_cast<bind_action_t>(result);
}

void
emulate_unbind(single_instance_hook_t& hook, uint64_t pid, const char* appid)
{
    uint32_t result;
    std::string app_id = appid;
    bind_md_t ctx{0};
    ctx.process_id = pid;
    ctx.operation = BIND_OPERATION_UNBIND;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
}

void
set_bind_limit(ebpf_handle_t handle, uint32_t limit)
{
    uint32_t limit_key = 0;
    REQUIRE(
        ebpf_api_map_update_element(handle, sizeof(limit_key), (uint8_t*)&limit_key, sizeof(limit), (uint8_t*)&limit) ==
        EBPF_SUCCESS);
}

TEST_CASE("bindmonitor-interpret", "[bindmonitor_interpret]")
{
    _test_helper test_helper;

    ebpf_handle_t program_handle;
    const char* error_message = NULL;
    ebpf_handle_t map_handles[4];
    uint32_t count_of_map_handles = 2;
    uint64_t fake_pid = 12345;
    uint32_t result;

    program_information_provider_t bind_program_information(EBPF_PROGRAM_TYPE_BIND);

    REQUIRE(
        (result = ebpf_api_load_program(
             SAMPLE_PATH "bindmonitor.o",
             "bind",
             EBPF_EXECUTION_INTERPRET,
             &program_handle,
             &count_of_map_handles,
             map_handles,
             &error_message),
         error_message ? printf("ebpf_api_load_program failed with %s\n", error_message) : 0,
         ebpf_api_free_string(error_message),
         error_message = nullptr,
         result == EBPF_SUCCESS));

    single_instance_hook_t hook;

    std::string process_maps_name = "bindmonitor::process_maps";
    std::string limit_maps_name = "bindmonitor::limits_map";

    REQUIRE(
        ebpf_api_pin_object(
            map_handles[0],
            reinterpret_cast<const uint8_t*>(process_maps_name.c_str()),
            static_cast<uint32_t>(process_maps_name.size())) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_api_pin_object(
            map_handles[1],
            reinterpret_cast<const uint8_t*>(limit_maps_name.c_str()),
            static_cast<uint32_t>(limit_maps_name.size())) == EBPF_SUCCESS);

    ebpf_handle_t test_handle;
    REQUIRE(
        ebpf_api_get_pinned_map(
            reinterpret_cast<const uint8_t*>(process_maps_name.c_str()),
            static_cast<uint32_t>(process_maps_name.size()),
            &map_handles[2]) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_api_get_pinned_map(
            reinterpret_cast<const uint8_t*>(limit_maps_name.c_str()),
            static_cast<uint32_t>(limit_maps_name.size()),
            &map_handles[3]) == EBPF_SUCCESS);

    REQUIRE(
        ebpf_api_unpin_object(
            reinterpret_cast<const uint8_t*>(process_maps_name.c_str()),
            static_cast<uint32_t>(process_maps_name.size())) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_api_unpin_object(
            reinterpret_cast<const uint8_t*>(limit_maps_name.c_str()), static_cast<uint32_t>(limit_maps_name.size())) ==
        EBPF_SUCCESS);
    REQUIRE(
        ebpf_api_get_pinned_map(
            reinterpret_cast<const uint8_t*>(process_maps_name.c_str()),
            static_cast<uint32_t>(process_maps_name.size()),
            &test_handle) == ERROR_NOT_FOUND);
    REQUIRE(
        ebpf_api_get_pinned_map(
            reinterpret_cast<const uint8_t*>(limit_maps_name.c_str()),
            static_cast<uint32_t>(limit_maps_name.size()),
            &test_handle) == ERROR_NOT_FOUND);

    ebpf_handle_t handle_iterator = INVALID_HANDLE_VALUE;
    REQUIRE(ebpf_api_get_next_map(handle_iterator, &handle_iterator) == EBPF_SUCCESS);
    REQUIRE(ebpf_api_get_next_map(handle_iterator, &handle_iterator) == EBPF_SUCCESS);
    REQUIRE(ebpf_api_get_next_map(handle_iterator, &handle_iterator) == EBPF_SUCCESS);
    REQUIRE(handle_iterator == INVALID_HANDLE_VALUE);

    hook.attach(program_handle);

    // Apply policy of maximum 2 binds per process
    set_bind_limit(map_handles[1], 2);

    // Bind first port - success
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

    // Bind second port - success
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 2);

    // Bind third port - blocked
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_DENY);
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 2);

    // Unbind second port
    emulate_unbind(hook, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

    // Unbind first port
    emulate_unbind(hook, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 0);

    // Bind from two apps to test enumeration
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

    fake_pid = 54321;
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_2") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

    uint64_t pid;
    REQUIRE(
        ebpf_api_get_next_map_key(map_handles[0], sizeof(uint64_t), NULL, reinterpret_cast<uint8_t*>(&pid)) ==
        EBPF_SUCCESS);
    REQUIRE(pid != 0);
    REQUIRE(
        ebpf_api_get_next_map_key(
            map_handles[0], sizeof(uint64_t), reinterpret_cast<uint8_t*>(&pid), reinterpret_cast<uint8_t*>(&pid)) ==
        EBPF_SUCCESS);
    REQUIRE(pid != 0);
    REQUIRE(
        ebpf_api_get_next_map_key(
            map_handles[0], sizeof(uint64_t), reinterpret_cast<uint8_t*>(&pid), reinterpret_cast<uint8_t*>(&pid)) ==
        ERROR_NO_MORE_ITEMS);

    hook.detach();
}

TEST_CASE("bindmonitor-jit", "[bindmonitor_jit]")
{
    _test_helper test_helper;

    ebpf_handle_t program_handle;
    const char* error_message = NULL;
    ebpf_handle_t map_handles[4];
    uint32_t count_of_map_handles = 2;
    uint64_t fake_pid = 12345;
    uint32_t result;

    program_information_provider_t bind_program_information(EBPF_PROGRAM_TYPE_BIND);

    REQUIRE(
        (result = ebpf_api_load_program(
             SAMPLE_PATH "bindmonitor.o",
             "bind",
             EBPF_EXECUTION_JIT,
             &program_handle,
             &count_of_map_handles,
             map_handles,
             &error_message),
         error_message ? printf("ebpf_api_load_program failed with %s\n", error_message) : 0,
         ebpf_api_free_string(error_message),
         error_message = nullptr,
         result == EBPF_SUCCESS));

    single_instance_hook_t hook;

    std::string process_maps_name = "bindmonitor::process_maps";
    std::string limit_maps_name = "bindmonitor::limits_map";

    REQUIRE(
        ebpf_api_pin_object(
            map_handles[0],
            reinterpret_cast<const uint8_t*>(process_maps_name.c_str()),
            static_cast<uint32_t>(process_maps_name.size())) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_api_pin_object(
            map_handles[1],
            reinterpret_cast<const uint8_t*>(limit_maps_name.c_str()),
            static_cast<uint32_t>(limit_maps_name.size())) == EBPF_SUCCESS);

    ebpf_handle_t test_handle;
    REQUIRE(
        ebpf_api_get_pinned_map(
            reinterpret_cast<const uint8_t*>(process_maps_name.c_str()),
            static_cast<uint32_t>(process_maps_name.size()),
            &map_handles[2]) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_api_get_pinned_map(
            reinterpret_cast<const uint8_t*>(limit_maps_name.c_str()),
            static_cast<uint32_t>(limit_maps_name.size()),
            &map_handles[3]) == EBPF_SUCCESS);

    REQUIRE(
        ebpf_api_unpin_object(
            reinterpret_cast<const uint8_t*>(process_maps_name.c_str()),
            static_cast<uint32_t>(process_maps_name.size())) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_api_unpin_object(
            reinterpret_cast<const uint8_t*>(limit_maps_name.c_str()), static_cast<uint32_t>(limit_maps_name.size())) ==
        EBPF_SUCCESS);
    REQUIRE(
        ebpf_api_get_pinned_map(
            reinterpret_cast<const uint8_t*>(process_maps_name.c_str()),
            static_cast<uint32_t>(process_maps_name.size()),
            &test_handle) == ERROR_NOT_FOUND);
    REQUIRE(
        ebpf_api_get_pinned_map(
            reinterpret_cast<const uint8_t*>(limit_maps_name.c_str()),
            static_cast<uint32_t>(limit_maps_name.size()),
            &test_handle) == ERROR_NOT_FOUND);

    ebpf_handle_t handle_iterator = INVALID_HANDLE_VALUE;
    REQUIRE(ebpf_api_get_next_map(handle_iterator, &handle_iterator) == EBPF_SUCCESS);
    REQUIRE(ebpf_api_get_next_map(handle_iterator, &handle_iterator) == EBPF_SUCCESS);
    REQUIRE(ebpf_api_get_next_map(handle_iterator, &handle_iterator) == EBPF_SUCCESS);
    REQUIRE(handle_iterator == INVALID_HANDLE_VALUE);

    hook.attach(program_handle);

    // Apply policy of maximum 2 binds per process
    set_bind_limit(map_handles[1], 2);

    // Bind first port - success
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

    // Bind second port - success
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 2);

    // Bind third port - blocked
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_DENY);
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 2);

    // Unbind second port
    emulate_unbind(hook, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

    // Unbind first port
    emulate_unbind(hook, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 0);

    // Bind from two apps to test enumeration
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

    fake_pid = 54321;
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_2") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

    uint64_t pid;
    REQUIRE(
        ebpf_api_get_next_map_key(map_handles[0], sizeof(uint64_t), NULL, reinterpret_cast<uint8_t*>(&pid)) ==
        EBPF_SUCCESS);
    REQUIRE(pid != 0);
    REQUIRE(
        ebpf_api_get_next_map_key(
            map_handles[0], sizeof(uint64_t), reinterpret_cast<uint8_t*>(&pid), reinterpret_cast<uint8_t*>(&pid)) ==
        EBPF_SUCCESS);
    REQUIRE(pid != 0);
    REQUIRE(
        ebpf_api_get_next_map_key(
            map_handles[0], sizeof(uint64_t), reinterpret_cast<uint8_t*>(&pid), reinterpret_cast<uint8_t*>(&pid)) ==
        ERROR_NO_MORE_ITEMS);

    hook.detach();
}

TEST_CASE("enumerate_and_query_programs", "[enumerate_and_query_programs]")
{
    _test_helper test_helper;

    ebpf_handle_t program_handle;
    ebpf_handle_t map_handles[3];
    uint32_t count_of_map_handle = 1;
    const char* error_message = NULL;
    uint32_t result;
    const char* file_name = nullptr;
    const char* section_name = nullptr;

    program_information_provider_t xdp_program_information(EBPF_PROGRAM_TYPE_XDP);

    REQUIRE(
        (result = ebpf_api_load_program(
             SAMPLE_PATH "droppacket.o",
             "xdp",
             EBPF_EXECUTION_JIT,
             &program_handle,
             &count_of_map_handle,
             map_handles,
             &error_message),
         ebpf_api_free_string(error_message),
         error_message ? printf("ebpf_api_load_program failed with %s\n", error_message) : 0,
         error_message = nullptr,
         result == EBPF_SUCCESS));

    REQUIRE(
        (result = ebpf_api_load_program(
             SAMPLE_PATH "droppacket.o",
             "xdp",
             EBPF_EXECUTION_INTERPRET,
             &program_handle,
             &count_of_map_handle,
             map_handles,
             &error_message),
         ebpf_api_free_string(error_message),
         error_message ? printf("ebpf_api_load_program failed with %s\n", error_message) : 0,
         error_message = nullptr,
         result == EBPF_SUCCESS));

    ebpf_execution_type_t type;
    program_handle = INVALID_HANDLE_VALUE;
    REQUIRE(ebpf_api_get_next_program(program_handle, &program_handle) == EBPF_SUCCESS);
    REQUIRE(ebpf_api_program_query_information(program_handle, &type, &file_name, &section_name) == EBPF_SUCCESS);
    REQUIRE(type == EBPF_EXECUTION_JIT);
    REQUIRE(strcmp(file_name, SAMPLE_PATH "droppacket.o") == 0);
    ebpf_api_free_string(file_name);
    file_name = nullptr;
    REQUIRE(strcmp(section_name, "xdp") == 0);
    REQUIRE(program_handle != INVALID_HANDLE_VALUE);
    ebpf_api_free_string(section_name);
    section_name = nullptr;
    REQUIRE(ebpf_api_get_next_program(program_handle, &program_handle) == EBPF_SUCCESS);
    REQUIRE(program_handle != INVALID_HANDLE_VALUE);
    REQUIRE(ebpf_api_program_query_information(program_handle, &type, &file_name, &section_name) == EBPF_SUCCESS);
    REQUIRE(type == EBPF_EXECUTION_INTERPRET);
    REQUIRE(strcmp(file_name, SAMPLE_PATH "droppacket.o") == 0);
    REQUIRE(strcmp(section_name, "xdp") == 0);
    ebpf_api_free_string(file_name);
    ebpf_api_free_string(section_name);
    file_name = nullptr;
    section_name = nullptr;
    REQUIRE(ebpf_api_get_next_program(program_handle, &program_handle) == EBPF_SUCCESS);
    REQUIRE(program_handle == INVALID_HANDLE_VALUE);
}

TEST_CASE("pinned_map_enum", "[pinned_map_enum]")
{
    _test_helper test_helper;

    ebpf_test_pinned_map_enum();
}
