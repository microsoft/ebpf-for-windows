// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "api_test.h"
#include "api_test_jit.h"
#include "bpf/libbpf.h"
#include "common_tests.h"
#include "misc_helper.h"
#include "native_helper.hpp"
#include "program_helper.h"
#include "service_helper.h"
#include "socket_helper.h"

#define _NTDEF_ // UNICODE_STRING is already defined.
#include <ntsecapi.h>

void
tailcall_load_test(_In_z_ const char* file_name)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;

    result = program_load_helper(file_name, BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == 0);

    REQUIRE(program_fd > 0);

    // Set up tail calls.
    struct bpf_program* callee0 = bpf_object__find_program_by_name(object, "callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(object, "callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    // Test a legacy libbpf api alias.
    REQUIRE(bpf_program__get_type(callee0) == BPF_PROG_TYPE_SAMPLE);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(object, "map");
    REQUIRE(prog_map_fd > 0);

    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    // Cleanup tail calls.
    index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

    bpf_object__close(object);
}

// Tests the following helper functions:
// 1. bpf_get_current_pid_tgid()
// 2. bpf_get_current_logon_id()
// 3. bpf_is_current_admin()
void
bpf_user_helpers_test(ebpf_execution_type_t execution_type)
{
    struct bpf_object* object = nullptr;
    uint64_t process_thread_id = get_current_pid_tgid();
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    native_module_helper_t module_helper;
    module_helper.initialize("bindmonitor", execution_type);
    program_load_attach_helper_t _helper;
    _helper.initialize(
        module_helper.get_file_name().c_str(), BPF_PROG_TYPE_BIND, "BindMonitor", execution_type, nullptr, 0, hook);
    object = _helper.get_object();

    perform_socket_bind(0, true);

    // Validate the contents of the audit map.
    fd_t audit_map_fd = bpf_object__find_map_fd_by_name(object, "audit_map");
    REQUIRE(audit_map_fd > 0);

    audit_entry_t entry = {0};
    int result = bpf_map_lookup_elem(audit_map_fd, &process_thread_id, &entry);
    REQUIRE(result == 0);

    REQUIRE(entry.is_admin == -1);

    REQUIRE(entry.logon_id != 0);
    SECURITY_LOGON_SESSION_DATA* data = NULL;
    result = LsaGetLogonSessionData((PLUID)&entry.logon_id, &data);
    REQUIRE(result == ERROR_SUCCESS);

    LsaFreeReturnBuffer(data);
}

void
perform_socket_bind(const uint16_t test_port, bool expect_success = true)
{
    WSAData data;
    int error = WSAStartup(2, &data);
    if (error != 0) {
        FAIL("Unable to load Winsock: " << error);
        return;
    }

    SOCKET _socket = INVALID_SOCKET;
    _socket = WSASocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, 0);
    REQUIRE(_socket != INVALID_SOCKET);
    uint32_t ipv6_option = 0;
    REQUIRE(
        setsockopt(
            _socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_option), sizeof(unsigned long)) ==
        0);
    SOCKADDR_STORAGE sock_addr;
    sock_addr.ss_family = AF_INET6;
    INETADDR_SETANY((PSOCKADDR)&sock_addr);

    // Perform bind operation.
    ((PSOCKADDR_IN6)&sock_addr)->sin6_port = htons(test_port);
    if (expect_success) {
        REQUIRE(bind(_socket, (PSOCKADDR)&sock_addr, sizeof(sock_addr)) == 0);
    } else {
        REQUIRE(bind(_socket, (PSOCKADDR)&sock_addr, sizeof(sock_addr)) != 0);
    }

    WSACleanup();
}

void
ring_buffer_api_test(ebpf_execution_type_t execution_type)
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper;
    _helper.initialize("bindmonitor_ringbuf.o", BPF_PROG_TYPE_BIND, "bind_monitor", execution_type, nullptr, 0, hook);
    object = _helper.get_object();

    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    REQUIRE(process_map_fd > 0);

    // Create a list of fake app IDs and set it to event context.
    std::wstring app_id = L"api_test.exe";
    std::vector<std::vector<char>> app_ids;
    char* p = reinterpret_cast<char*>(&app_id[0]);
    std::vector<char> temp(p, p + (app_id.size() + 1) * sizeof(wchar_t));

    // ring_buffer_api_test_helper expects a list of app IDs of size RING_BUFFER_TEST_EVENT_COUNT.
    for (auto i = 0; i < RING_BUFFER_TEST_EVENT_COUNT; i++) {
        app_ids.push_back(temp);
    }

    ring_buffer_api_test_helper(process_map_fd, app_ids, [](int i) {
        const uint16_t _test_port = 12345 + static_cast<uint16_t>(i);
        perform_socket_bind(_test_port);
    });
}

// See also divide_by_zero_test_um in end_to_end.cpp for the user-mode equivalent.
void
divide_by_zero_test_km(ebpf_execution_type_t execution_type)
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper;
    _helper.initialize("divide_by_zero.o", BPF_PROG_TYPE_BIND, "divide_by_zero", execution_type, nullptr, 0, hook);
    object = _helper.get_object();

    perform_socket_bind(0, true);

    // If we don't bug-check, the test passed.
}

int32_t
get_expected_jit_result(int32_t expected_result)
{
#if defined(CONFIG_BPF_JIT_DISABLED)
    UNREFERENCED_PARAMETER(expected_result);
    return -ENOTSUP;
#else
    return expected_result;
#endif
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("test_ebpf_program_next_previous_jit", "[test_ebpf_program_next_previous]")
{
    test_program_next_previous("test_sample_ebpf.o", SAMPLE_PROGRAM_COUNT);
    test_program_next_previous("bindmonitor.o", BIND_MONITOR_PROGRAM_COUNT);
}

TEST_CASE("test_ebpf_map_next_previous_jit", "[test_ebpf_map_next_previous]")
{
    test_map_next_previous("test_sample_ebpf.o", SAMPLE_MAP_COUNT);
    test_map_next_previous("bindmonitor.o", BIND_MONITOR_MAP_COUNT);
}

TEST_CASE("ringbuf_api_jit", "[test_ringbuf_api][ring_buffer]") { ring_buffer_api_test(EBPF_EXECUTION_JIT); }
TEST_CASE("divide_by_zero_jit", "[divide_by_zero]") { divide_by_zero_test_km(EBPF_EXECUTION_JIT); }

TEST_CASE("tailcall_load_test_jit", "[tailcall_load_test]") { tailcall_load_test("tail_call_multiple.o"); }

TEST_CASE("bpf_user_helpers_test_jit", "[api_test]") { bpf_user_helpers_test(EBPF_EXECUTION_JIT); }
#endif

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("ringbuf_api_interpret", "[test_ringbuf_api][ring_buffer]")
{
    ring_buffer_api_test(EBPF_EXECUTION_INTERPRET);
}
TEST_CASE("divide_by_zero_interpret", "[divide_by_zero]") { divide_by_zero_test_km(EBPF_EXECUTION_INTERPRET); }
#endif