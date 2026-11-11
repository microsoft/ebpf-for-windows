// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_test.h"
#include "api_test_jit.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "misc_helper.h"
#include "program_helper.h"
#include "sample_test_common.h"
#include "socket_helper.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <mstcpip.h>
#define _NTDEF_ // UNICODE_STRING is already defined.
#include "usersim/nt_process_info.h"

#include <ntsecapi.h>
#include <processthreadsapi.h>
#include <vector>

static void
_test_program_load(
    const char* file_name, bpf_prog_type program_type, ebpf_execution_type_t execution_type, int expected_load_result)
{
    struct bpf_object* object = nullptr;
    fd_t program_fd;

    int result = program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
    REQUIRE(result == expected_load_result);
    if (expected_load_result != 0) {
        return;
    }

    REQUIRE(program_fd > 0);
    uint32_t next_id;
    REQUIRE(bpf_prog_get_next_id(0, &next_id) == 0);

    program_fd = bpf_prog_get_fd_by_id(next_id);
    REQUIRE(program_fd > 0);

    const char* program_file_name = nullptr;
    const char* program_section_name = nullptr;
    ebpf_execution_type_t program_execution_type;
    REQUIRE(
        ebpf_program_query_info(program_fd, &program_execution_type, &program_file_name, &program_section_name) ==
        EBPF_SUCCESS);
    _close(program_fd);

    if (execution_type == EBPF_EXECUTION_ANY) {
        execution_type = EBPF_EXECUTION_JIT;
    }
    REQUIRE(program_execution_type == execution_type);
    if (execution_type != EBPF_EXECUTION_NATIVE) {
        REQUIRE(strcmp(program_file_name, file_name) == 0);
    }

    ebpf_free_string(program_file_name);
    ebpf_free_string(program_section_name);
    uint32_t previous_id = next_id;
    REQUIRE(bpf_prog_get_next_id(previous_id, &next_id) == -ENOENT);

    bpf_object__close(object);
    REQUIRE(bpf_prog_get_next_id(0, &next_id) == -ENOENT);
}

#define DECLARE_LOAD_TEST_CASE(file, program_type, execution_type, expected_result)  \
    TEST_CASE("test_ebpf_program_load-" #file "-" #program_type "-" #execution_type) \
    {                                                                                \
        _test_program_load(file, program_type, execution_type, expected_result);     \
    }

#if defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define INTERPRET_LOAD_RESULT -ENOTSUP
#else
#define INTERPRET_LOAD_RESULT 0
#endif

// Program and map enumeration for bindmonitor belongs with the network extension tests.
#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("bind_program_next_previous_jit", "[netebpfext]")
{
    test_program_next_previous("bindmonitor.o", BIND_MONITOR_PROGRAM_COUNT);
}

TEST_CASE("bind_map_next_previous_jit", "[netebpfext]")
{
    test_map_next_previous("bindmonitor.o", BIND_MONITOR_MAP_COUNT);
}
#endif

TEST_CASE("bind_program_next_previous_native", "[netebpfext]")
{
    test_program_next_previous("bindmonitor.sys", BIND_MONITOR_PROGRAM_COUNT);
}

TEST_CASE("bind_map_next_previous_native", "[netebpfext]")
{
    test_map_next_previous("bindmonitor.sys", BIND_MONITOR_MAP_COUNT);
}

DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_BIND, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_ANY, get_expected_jit_result(-EACCES));

TEST_CASE("netebpfext_enumerate_programs", "[netebpfext]")
{
    ebpf_api_program_info_t* program_infos = nullptr;
    const char* error_message = nullptr;

    ebpf_result_t result = ebpf_enumerate_programs("bindmonitor.o", false, &program_infos, &error_message);
    if (result == EBPF_SUCCESS && program_infos != nullptr) {
        REQUIRE(program_infos->section_name != nullptr);
        REQUIRE(std::string(program_infos->section_name) == "bind");
        REQUIRE(std::string(program_infos->program_name) == "BindMonitor");
        REQUIRE(program_infos->program_type == EBPF_PROGRAM_TYPE_BIND);
        REQUIRE(program_infos->expected_attach_type == EBPF_ATTACH_TYPE_BIND);
        ebpf_free_programs(program_infos);
    }
    ebpf_free_string(error_message);
}

static int
_perform_bind(_Out_ SOCKET* socket, uint16_t port_number)
{
    *socket = WSASocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, 0);
    REQUIRE(*socket != INVALID_SOCKET);
    SOCKADDR_STORAGE sock_addr;
    sock_addr.ss_family = AF_INET6;
    INETADDR_SETANY((PSOCKADDR)&sock_addr);

    ((PSOCKADDR_IN6)&sock_addr)->sin6_port = htons(port_number);
    return bind(*socket, (PSOCKADDR)&sock_addr, sizeof(sock_addr));
}

static void
_test_bindmonitor_program(_In_ struct bpf_object* object)
{
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    REQUIRE(process_map_fd > 0);

    fd_t limits_map_fd = bpf_object__find_map_fd_by_name(object, "limits_map");
    REQUIRE(limits_map_fd > 0);

    // Set the limit to 2. The third bind from the same app should fail.
    uint32_t key = 0;
    uint32_t value = 2;
    REQUIRE(bpf_map_update_elem(limits_map_fd, &key, &value, 0) == 0);

    WSAData data{};
    SOCKET sockets[3]{};
    REQUIRE(WSAStartup(2, &data) == 0);
    auto winsock_cleanup =
        std::unique_ptr<void, void (*)(void*)>(reinterpret_cast<void*>(1), [](void*) { WSACleanup(); });

    REQUIRE(_perform_bind(&sockets[0], 30000) == 0);
    REQUIRE(_perform_bind(&sockets[1], 30001) == 0);
    REQUIRE(_perform_bind(&sockets[2], 30002) != 0);
    for (SOCKET socket : sockets) {
        if (socket != INVALID_SOCKET) {
            closesocket(socket);
        }
    }
}

TEST_CASE("bindmonitor_native_test", "[netebpfext]")
{
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t helper;
    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor", EBPF_EXECUTION_NATIVE);
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        "BindMonitor",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);

    _test_bindmonitor_program(helper.get_object());
}

TEST_CASE("bindmonitor_tailcall_native_test", "[netebpfext]")
{
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t helper;
    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor_tailcall", EBPF_EXECUTION_NATIVE);
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        "BindMonitor",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);
    bpf_object* object = helper.get_object();

    bpf_program* callee0 = bpf_object__find_program_by_name(object, "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    bpf_program* callee1 = bpf_object__find_program_by_name(object, "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(object, "prog_array_map");
    REQUIRE(prog_map_fd > 0);
    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    _test_bindmonitor_program(object);

    auto cleanup = [&]() {
        index = 0;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
        index = 1;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    };

    REQUIRE(bpf_object__find_map_by_name(object, "dummy_outer_map") != nullptr);
    REQUIRE(bpf_object__find_map_by_name(object, "dummy_outer_idx_map") != nullptr);
    cleanup();
}

// Tests the following helper functions via the bindmonitor program:
// 1. bpf_get_current_pid_tgid()
// 2. bpf_get_current_logon_id()
// 3. bpf_is_current_admin()
static void
_bpf_user_helpers_test(ebpf_execution_type_t execution_type)
{
    uint64_t process_thread_id = get_current_pid_tgid();
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    native_module_helper_t module_helper;
    module_helper.initialize("bindmonitor", execution_type);
    program_load_attach_helper_t helper;
    helper.initialize(
        module_helper.get_file_name().c_str(), BPF_PROG_TYPE_BIND, "BindMonitor", execution_type, nullptr, 0, hook);
    struct bpf_object* object = helper.get_object();

    WSAData data{};
    REQUIRE(WSAStartup(2, &data) == 0);
    auto winsock_cleanup =
        std::unique_ptr<void, void (*)(void*)>(reinterpret_cast<void*>(1), [](void*) { WSACleanup(); });

    SOCKET sock = INVALID_SOCKET;
    REQUIRE(_perform_bind(&sock, 0) == 0);
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }

    // Validate the contents of the audit map.
    fd_t audit_map_fd = bpf_object__find_map_fd_by_name(object, "audit_map");
    REQUIRE(audit_map_fd > 0);

    audit_entry_t entry = {0};
    int result = bpf_map_lookup_elem(audit_map_fd, &process_thread_id, &entry);
    REQUIRE(result == 0);

    REQUIRE(entry.is_admin == -1);

    REQUIRE(entry.logon_id != 0);
    SECURITY_LOGON_SESSION_DATA* session_data = NULL;
    result = LsaGetLogonSessionData((PLUID)&entry.logon_id, &session_data);
    REQUIRE(result == ERROR_SUCCESS);

    LsaFreeReturnBuffer(session_data);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("bpf_user_helpers_test_jit", "[netebpfext]") { _bpf_user_helpers_test(EBPF_EXECUTION_JIT); }
#endif

TEST_CASE("bpf_user_helpers_test_native", "[netebpfext]") { _bpf_user_helpers_test(EBPF_EXECUTION_NATIVE); }

struct _ebpf_program_load_test_parameters
{
    _Field_z_ const char* file_name;
    bpf_prog_type prog_type;
};

static void
_test_multiple_programs_load(
    int program_count,
    _In_reads_(program_count) const struct _ebpf_program_load_test_parameters* parameters,
    ebpf_execution_type_t execution_type,
    int expected_load_result)
{
    int result;
    std::vector<struct bpf_object*> objects;

    for (int i = 0; i < program_count; i++) {
        const char* file_name = parameters[i].file_name;
        bpf_prog_type program_type = parameters[i].prog_type;
        struct bpf_object* object;
        fd_t program_fd;

        result = program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
        CAPTURE(file_name);
        REQUIRE(expected_load_result == result);
        if (expected_load_result == 0) {
            REQUIRE(program_fd > 0);
        } else {
            continue;
        }

        objects.push_back(object);
    }

    if (expected_load_result != 0) {
        return;
    }

    for (int i = 0; i < program_count; i++) {
        bpf_object__close(objects[i]);
    }
}

TEST_CASE("load_all_sample_programs", "[native_tests]")
{
    struct _ebpf_program_load_test_parameters test_parameters[] = {
        {"bindmonitor.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_bpf2bpf.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_mt_tailcall.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_perf_event_array.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_ringbuf.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_tailcall.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_count_connect4.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_count_connect6.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_mt_connect4.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_mt_connect6.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_sock_addr.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_sock_addr2.sys", BPF_PROG_TYPE_UNSPEC},
        {"process_start_key.sys", BPF_PROG_TYPE_UNSPEC},
        {"sockops.sys", BPF_PROG_TYPE_UNSPEC},
        {"thread_start_time.sys", BPF_PROG_TYPE_UNSPEC}};

    _test_multiple_programs_load(_countof(test_parameters), test_parameters, EBPF_EXECUTION_NATIVE, 0);
}

static uint64_t
read_pid_tgid(struct bpf_object* object)
{
    struct bpf_map* map = bpf_object__find_map_by_name(object, "pidtgid_map");
    REQUIRE(map != nullptr);
    uint32_t key = 0;
    uint64_t pid_tgid = 0;
    REQUIRE(bpf_map_lookup_elem(bpf_map__fd(map), &key, &pid_tgid) == 0);
    return pid_tgid;
}

TEST_CASE("bpf_get_current_pid_tgid_sock_addr", "[helpers]")
{
    native_module_helper_t native_helper;
    native_helper.initialize("pidtgid_netebpf", EBPF_EXECUTION_NATIVE);

    hook_helper_t hook(EBPF_ATTACH_TYPE_CGROUP_INET4_BIND);
    program_load_attach_helper_t helper;
    uint32_t compartment_id = 0;
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        "sock_addr_program",
        EBPF_EXECUTION_NATIVE,
        &compartment_id,
        sizeof(compartment_id),
        hook);

    wsa_helper_t wsa_helper;
    REQUIRE(wsa_helper.initialize() == 0);
    datagram_client_socket_t bound_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT, IPv4);

    uint64_t pid_tgid = read_pid_tgid(helper.get_object());
    REQUIRE(static_cast<uint32_t>(pid_tgid >> 32) == GetCurrentProcessId());
    REQUIRE(static_cast<uint32_t>(pid_tgid) == GetCurrentThreadId());
}

TEST_CASE("bpf_get_current_pid_tgid_sock_ops", "[helpers]")
{
    native_module_helper_t native_helper;
    native_helper.initialize("pidtgid_netebpf", EBPF_EXECUTION_NATIVE);

    hook_helper_t hook(EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS);
    program_load_attach_helper_t helper;
    uint32_t compartment_id = 0;
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_SOCK_OPS,
        "sock_ops_program",
        EBPF_EXECUTION_NATIVE,
        &compartment_id,
        sizeof(compartment_id),
        hook);

    wsa_helper_t wsa_helper;
    REQUIRE(wsa_helper.initialize() == 0);
    datagram_server_socket_t server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);
    datagram_client_socket_t client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    sockaddr_storage destination_address{};
    IN6ADDR_SETV4MAPPED(
        reinterpret_cast<PSOCKADDR_IN6>(&destination_address), &in4addr_loopback, scopeid_unspecified, 0);
    client_socket.send_message_to_remote_host(CLIENT_MESSAGE, destination_address, SOCKET_TEST_PORT);

    uint64_t pid_tgid = read_pid_tgid(helper.get_object());
    REQUIRE(static_cast<uint32_t>(pid_tgid >> 32) == GetCurrentProcessId());
    REQUIRE(static_cast<uint32_t>(pid_tgid) != 0);
}

// Intentionally leaves BIND program resources open to exercise core cleanup at process exit.
TEST_CASE("close_unload_test", "[native_tests][native_close_cleanup_tests]")
{
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t helper;
    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor_tailcall", EBPF_EXECUTION_NATIVE);
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        "BindMonitor",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);
    bpf_object* object = helper.get_object();

    bpf_program* callee0 = bpf_object__find_program_by_name(object, "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    bpf_program* callee1 = bpf_object__find_program_by_name(object, "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(object, "prog_array_map");
    REQUIRE(prog_map_fd > 0);
    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);
    index = 2;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);
    index = 4;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);
    index = 7;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    _test_bindmonitor_program(object);

    // The block of commented code after this comment is for documentation purposes only.
    //
    // A well-behaved user mode application _should_ call these calls to correctly free the allocated objects. In case
    // of careless applications that do not do so (or even well behaved applications, when they crash or terminate for
    // some reason before getting to this point), the 'premature application close' event handling _should_ take care
    // of reclaiming and free'ing such objects. All unit tests belonging to the '[native_close_cleanup_tests]'
    // unit-test class simulate this behavior by _not_ calling the clean-up api calls.
    //
    // For native tests (meant for execution on the kernel mode ebpf-for-windows driver), this event will be handled
    // by the ebpf-core kernel mode driver on test application termination.
    //
    // The success/failure of the [native_close_cleanup_tests] tests can only be (indirectly) checked by attempting to
    // stop the ebpf-core driver after executing this class of tests. If the clean-up by the ebpf-core driver is not
    // successful, it cannot be stopped/unloaded. This step is performed automatically by the CI/CD test pass runs and
    // will need to be performed as an explicit manual step after a manually initiated test-run.
    //
    // On a final note, each test in the [native_close_cleanup_tests] set _must_ load a .sys driver (if it needs one)
    // that either has not been loaded yet, or was loaded but has since been unloaded (before start of the test). Given
    // that we deliberately skip the clean-up API calls, the drivers stay loaded at the end of the individual test. An
    // attempt to (re)load the same driver again (by the next test) will fail (as it should), but leads to spurious
    // test failures (by way of an assert due to an error returned by bpf_object__load() in the
    // program_load_attach_helper_t constructor).

    /*
        --- DO NOT REMOVE OR UN-COMMENT ---

    auto cleanup = [prog_map_fd, &index]() {
        index = 0;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

        index = 1;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

        index = 2;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

        index = 4;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

        index = 7;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    };

    // Clean up tail calls.
    cleanup();

    // Free the program as well.
    bpf_object__close(object);
    */
}

static void
send_traffic(IPPROTO protocol, bool is_ipv6)
{
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    PSOCKADDR local_address = nullptr;
    int local_address_length = 0;

    if (protocol == IPPROTO_UDP) {
        datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
        datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);
        datagram_client_socket.get_local_address(local_address, local_address_length);
        datagram_server_socket.post_async_receive();

        if (is_ipv6) {
            IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
        } else {
            IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
        }

        datagram_client_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
        datagram_server_socket.complete_async_receive(false);
        datagram_client_socket.cancel_pending_io();
    } else // TCP traffic.
    {
        stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
        stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);
        stream_client_socket.get_local_address(local_address, local_address_length);
        stream_server_socket.post_async_receive();

        if (is_ipv6) {
            IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
        } else {
            IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
        }

        stream_client_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
        stream_server_socket.complete_async_receive(false);
        stream_client_socket.cancel_pending_io();
    }
}

/**
 * @brief Look up the process start key for a given PID, for comparison against the value reported by
 * bpf_get_current_process_start_key (PsGetProcessStartKey in the kernel).
 * @param[in] pid Process ID whose start key to query.
 * @param[out] start_key On success, receives the process start key.
 * @returns true if the start key was obtained; false (with a warning) if the process could not be
 *  opened or queried.
 */
static bool
try_get_process_start_key(uint32_t pid, uint64_t& start_key)
{
    // PROCESS_TELEMETRY_ID_INFORMATION and the NtQueryInformationProcess prototype come from
    // usersim/nt_process_info.h. They are declared there (rather than pulled from <winternl.h>)
    // because <winternl.h> redefines _STRING/UNICODE_STRING already provided by <ntsecapi.h>
    // (used elsewhere in this file), producing C2011. Resolve the function at runtime via
    // GetProcAddress to avoid an ntdll.lib link dependency.
    // See https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
    static NtQueryInformationProcess_t nt_query_information_process = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    REQUIRE(nt_query_information_process != nullptr);

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) {
        std::cout << "WARNING: OpenProcess(pid=" << pid << ") failed, err=" << GetLastError()
                  << "; skipping process start-key consistency check\n";
        return false;
    }

    bool succeeded = false;
    // ProcessTelemetryIdInformation returns the fixed struct followed by variable-length data
    // (user SID, image path, package/app name, command line) referenced by the trailing *Offset
    // fields, so the query needs a buffer larger than the struct itself. Start with headroom and
    // grow once if the process reports it needs more.
    std::vector<uint8_t> buffer(sizeof(PROCESS_TELEMETRY_ID_INFORMATION) + 1024);
    ULONG return_length = 0;
    NTSTATUS status = nt_query_information_process(
        process, ProcessTelemetryIdInformation, buffer.data(), static_cast<ULONG>(buffer.size()), &return_length);
    if (status != STATUS_SUCCESS && return_length > buffer.size()) {
        buffer.resize(return_length);
        status = nt_query_information_process(
            process, ProcessTelemetryIdInformation, buffer.data(), static_cast<ULONG>(buffer.size()), &return_length);
    }
    if (status == STATUS_SUCCESS && return_length >= sizeof(PROCESS_TELEMETRY_ID_INFORMATION)) {
        start_key = reinterpret_cast<const PROCESS_TELEMETRY_ID_INFORMATION*>(buffer.data())->ProcessStartKey;
        succeeded = true;
    } else {
        std::cout << "WARNING: NtQueryInformationProcess(ProcessTelemetryIdInformation) failed, status=0x" << std::hex
                  << static_cast<unsigned long>(status) << std::dec
                  << "; skipping process start-key consistency check\n";
    }

    CloseHandle(process);
    return succeeded;
}

static void
run_process_start_key_test(IPPROTO protocol, bool is_ipv6)
{
    hook_helper_t hook(is_ipv6 ? EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT : EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT);
    uint32_t ifindex = 0;
    const char* program_name_ipv4 = "function_v4";
    const char* program_name_ipv6 = "function_v6";
    program_load_attach_helper_t helper;
    native_module_helper_t native_helper;
    struct bpf_map* map = nullptr;
    wsa_helper_t wsa_helper;
    native_helper.initialize("process_start_key", EBPF_EXECUTION_NATIVE);
    {
        helper.initialize(
            native_helper.get_file_name().c_str(),
            BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            is_ipv6 ? program_name_ipv6 : program_name_ipv4,
            EBPF_EXECUTION_NATIVE,
            &ifindex,
            sizeof(ifindex),
            hook);
        struct bpf_object* object = helper.get_object();

        wsa_helper.initialize();
        send_traffic(protocol, is_ipv6);

        std::cout << "bpf_object__find_map_by_name(process_start_key_map)\n";
        map = bpf_object__find_map_by_name(object, "process_start_key_map");
        REQUIRE(map != nullptr);
        REQUIRE(map->map_fd != ebpf_fd_invalid);

        uint32_t key = 0;
        process_start_key_value_t found_value{};
        std::cout << "bpf_map_lookup_elem(process_start_key_map) key: " << key << "\n";
        REQUIRE(bpf_map_lookup_elem(bpf_map__fd(map), &key, &found_value) == 0);

        std::cout << "bpf_map_delete_elem(process_start_key_map)\n";
        REQUIRE(bpf_map_delete_elem(bpf_map__fd(map), &key) == 0);

        // Validate the captured (pid, start_key) pair for self-consistency: look up the captured
        // PID's process and compare its ProcessStartKey (PsGetProcessStartKey in the kernel) to the
        // helper-reported start_key. The WFP ALE_AUTH_CONNECT callout is not guaranteed to run on
        // the caller's process, so we do NOT assume current_pid is ours — only that the reported
        // pair is internally consistent.
        REQUIRE(found_value.current_pid > 0);
        REQUIRE(0 < found_value.start_key);
        uint64_t process_start_key = 0;
        if (try_get_process_start_key(found_value.current_pid, process_start_key)) {
            REQUIRE(process_start_key == found_value.start_key);
        }
    }
}

static void
run_thread_start_time_test(IPPROTO protocol, bool is_ipv6)
{
    hook_helper_t hook(is_ipv6 ? EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT : EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT);
    uint32_t ifindex = 0;
    const char* program_name_ipv4 = "function_v4";
    const char* program_name_ipv6 = "function_v6";
    program_load_attach_helper_t helper;
    native_module_helper_t native_helper;
    struct bpf_map* map = nullptr;
    wsa_helper_t wsa_helper;
    native_helper.initialize("thread_start_time", EBPF_EXECUTION_NATIVE);
    {
        helper.initialize(
            native_helper.get_file_name().c_str(),
            BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            is_ipv6 ? program_name_ipv6 : program_name_ipv4,
            EBPF_EXECUTION_NATIVE,
            &ifindex,
            sizeof(ifindex),
            hook);
        struct bpf_object* object = helper.get_object();

        wsa_helper.initialize();
        send_traffic(protocol, is_ipv6);

        std::cout << "bpf_object__find_map_by_name(thread_start_time_map)\n";
        map = bpf_object__find_map_by_name(object, "thread_start_time_map");
        REQUIRE(map != nullptr);
        REQUIRE(map->map_fd != ebpf_fd_invalid);

        uint32_t key = 0;
        thread_start_time_value_t found_value{};
        std::cout << "bpf_map_lookup_elem(thread_start_time_map) key: " << key << "\n";
        REQUIRE(bpf_map_lookup_elem(bpf_map__fd(map), &key, &found_value) == 0);

        std::cout << "bpf_map_delete_elem(thread_start_time_map)\n";
        REQUIRE(bpf_map_delete_elem(bpf_map__fd(map), &key) == 0);

        // Validate the captured (tid, start_time) pair for self-consistency: open the captured
        // thread and compare its creation time to the helper-reported start_time
        // (bpf_get_current_thread_create_time -> PsGetThreadCreateTime, which is FILETIME-compatible
        // 100ns-since-1601 units). The WFP ALE_AUTH_CONNECT callout is not guaranteed to run on the
        // caller's thread, so we do NOT assume current_tid is ours — only that the pair is consistent.
        REQUIRE(found_value.current_tid > 0);
        REQUIRE(found_value.start_time > 0);
        HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, found_value.current_tid);
        if (thread == nullptr) {
            std::cout << "WARNING: OpenThread(tid=" << found_value.current_tid << ") failed, err=" << GetLastError()
                      << "; skipping thread create-time consistency check\n";
        } else {
            FILETIME creation_time, exit_time, kernel_time, user_time;
            REQUIRE(GetThreadTimes(thread, &creation_time, &exit_time, &kernel_time, &user_time));
            int64_t creation_time_100ns =
                (static_cast<int64_t>(creation_time.dwHighDateTime) << 32) | creation_time.dwLowDateTime;
            REQUIRE(creation_time_100ns == found_value.start_time);
            CloseHandle(thread);
        }
    }
}

TEST_CASE("bpf_get_process_start_key_udp_ipv4", "[netebpfext]") { run_process_start_key_test(IPPROTO_UDP, false); }

TEST_CASE("bpf_get_process_start_key_udp_ipv6", "[netebpfext]") { run_process_start_key_test(IPPROTO_UDP, true); }

TEST_CASE("bpf_get_process_start_key_tcp_ipv4", "[netebpfext]") { run_process_start_key_test(IPPROTO_TCP, false); }

TEST_CASE("bpf_get_process_start_key_tcp_ipv6", "[netebpfext]") { run_process_start_key_test(IPPROTO_TCP, true); }

TEST_CASE("bpf_get_thread_start_time_udp_ipv4", "[netebpfext]") { run_thread_start_time_test(IPPROTO_UDP, false); }

TEST_CASE("bpf_get_thread_start_time_udp_ipv6", "[netebpfext]") { run_thread_start_time_test(IPPROTO_UDP, true); }

TEST_CASE("bpf_get_thread_start_time_tcp_ipv4", "[netebpfext]") { run_thread_start_time_test(IPPROTO_TCP, false); }

TEST_CASE("bpf_get_thread_start_time_tcp_ipv6", "[netebpfext]") { run_thread_start_time_test(IPPROTO_TCP, true); }
