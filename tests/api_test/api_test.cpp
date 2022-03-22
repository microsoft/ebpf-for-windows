// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <mutex>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#include "api_test.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include <io.h>
#include "program_helper.h"
#include "service_helper.h"
#define SAMPLE_PATH ""

#define EBPF_CORE_DRIVER_BINARY_NAME L"ebpfcore.sys"
#define EBPF_CORE_DRIVER_NAME L"ebpfcore"

#define EBPF_EXTENSION_DRIVER_BINARY_NAME L"netebpfext.sys"
#define EBPF_EXTENSION_DRIVER_NAME L"netebpfext"

#define EBPF_SERVICE_BINARY_NAME L"ebpfsvc.exe"
#define EBPF_SERVICE_NAME L"ebpfsvc"

#define DROP_PACKET_PROGRAM_COUNT 1
#define BIND_MONITOR_PROGRAM_COUNT 1

#define DROP_PACKET_MAP_COUNT 2
#define BIND_MONITOR_MAP_COUNT 2

static service_install_helper
    _ebpf_core_driver_helper(EBPF_CORE_DRIVER_NAME, EBPF_CORE_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_extension_driver_helper(EBPF_EXTENSION_DRIVER_NAME, EBPF_EXTENSION_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME, SERVICE_WIN32_OWN_PROCESS);

static ebpf_result_t
_program_load_helper(
    const char* file_name,
    const ebpf_program_type_t* program_type,
    ebpf_execution_type_t execution_type,
    struct bpf_object** object,
    fd_t* program_fd)
{
    ebpf_result_t result;
    const char* log_buffer = nullptr;
    result = ebpf_program_load(file_name, program_type, nullptr, execution_type, object, program_fd, &log_buffer);

    ebpf_free_string(log_buffer);
    return result;
}

static void
_test_program_load(
    const char* file_name,
    ebpf_program_type_t* program_type,
    ebpf_execution_type_t execution_type,
    ebpf_result_t expected_load_result)
{
    ebpf_result_t result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    fd_t previous_fd = ebpf_fd_invalid;
    fd_t next_fd = ebpf_fd_invalid;

    result = _program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
    REQUIRE(result == expected_load_result);

    if (expected_load_result == EBPF_SUCCESS) {
        REQUIRE(program_fd > 0);
    } else {
        return;
    }

    // Query loaded programs to verify this program is loaded.
    REQUIRE(ebpf_get_next_program(previous_fd, &next_fd) == EBPF_SUCCESS);
    REQUIRE(next_fd != ebpf_fd_invalid);

    const char* program_file_name;
    const char* program_section_name;
    ebpf_execution_type_t program_execution_type;
    REQUIRE(
        ebpf_program_query_info(program_fd, &program_execution_type, &program_file_name, &program_section_name) ==
        EBPF_SUCCESS);

    // Set the default execution type to JIT. This will eventually
    // be decided by a system-wide policy. TODO(Issue #288): Configure
    // system-wide execution type.
    if (execution_type == EBPF_EXECUTION_ANY) {
        execution_type = EBPF_EXECUTION_JIT;
    }
    REQUIRE(program_execution_type == execution_type);
    if (execution_type != EBPF_EXECUTION_NATIVE)
        REQUIRE(strcmp(program_file_name, file_name) == 0);

    // Next program should not be present.
    previous_fd = next_fd;
    REQUIRE(ebpf_get_next_program(previous_fd, &next_fd) == EBPF_SUCCESS);
    REQUIRE(next_fd == ebpf_fd_invalid);

    _close(previous_fd);
    previous_fd = ebpf_fd_invalid;
    bpf_object__close(object);

    // We have closed both handles to the program. Program should be unloaded now.
    REQUIRE(ebpf_get_next_program(previous_fd, &next_fd) == ERROR_SUCCESS);
    REQUIRE(next_fd == ebpf_fd_invalid);
}

static void
_test_map_next_previous(const char* file_name, int expected_map_count)
{
    ebpf_result_t result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int map_count = 0;
    struct bpf_map* previous = nullptr;
    struct bpf_map* next = nullptr;
    result = _program_load_helper(file_name, nullptr, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == EBPF_SUCCESS);

    next = bpf_map__next(previous, object);
    while (next != nullptr) {
        map_count++;
        previous = next;
        next = bpf_map__next(previous, object);
    }
    REQUIRE(map_count == expected_map_count);

    map_count = 0;
    previous = next = nullptr;

    previous = bpf_map__prev(next, object);
    while (previous != nullptr) {
        map_count++;
        next = previous;
        previous = bpf_map__prev(next, object);
    }
    REQUIRE(map_count == expected_map_count);

    bpf_object__close(object);
}

static void
_test_program_next_previous(const char* file_name, int expected_program_count)
{
    ebpf_result_t result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int program_count = 0;
    struct bpf_program* previous = nullptr;
    struct bpf_program* next = nullptr;
    result = _program_load_helper(file_name, nullptr, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == EBPF_SUCCESS);

    next = bpf_program__next(previous, object);
    while (next != nullptr) {
        program_count++;
        previous = next;
        next = bpf_program__next(previous, object);
    }
    REQUIRE(program_count == expected_program_count);

    program_count = 0;
    previous = next = nullptr;

    previous = bpf_program__prev(next, object);
    while (previous != nullptr) {
        program_count++;
        next = previous;
        previous = bpf_program__prev(next, object);
    }
    REQUIRE(program_count == expected_program_count);

    bpf_object__close(object);
}

TEST_CASE("pinned_map_enum", "[pinned_map_enum]") { ebpf_test_pinned_map_enum(); }

#define DECLARE_LOAD_TEST_CASE(file, program_type, execution_type, expected_result)  \
    TEST_CASE("test_ebpf_program_load-" #file "-" #program_type "-" #execution_type) \
    {                                                                                \
        _test_program_load(file, program_type, execution_type, expected_result);     \
    }

#if defined(CONFIG_BPF_JIT_ALWAYS_ON)
#define INTERPRET_LOAD_RESULT EBPF_PROGRAM_LOAD_FAILED
#else
#define INTERPRET_LOAD_RESULT EBPF_SUCCESS
#endif

// Load droppacket (JIT) without providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", nullptr, EBPF_EXECUTION_JIT, EBPF_SUCCESS);

DECLARE_LOAD_TEST_CASE("droppacket_km.sys", nullptr, EBPF_EXECUTION_NATIVE, EBPF_SUCCESS);

// Load droppacket (ANY) without providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", nullptr, EBPF_EXECUTION_ANY, EBPF_SUCCESS);

// Load droppacket (INTERPRET) without providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", nullptr, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load droppacket with providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", &EBPF_PROGRAM_TYPE_XDP, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load bindmonitor (JIT) without providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", nullptr, EBPF_EXECUTION_JIT, EBPF_SUCCESS);

// Load bindmonitor (INTERPRET) without providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", nullptr, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load bindmonitor with providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", &EBPF_PROGRAM_TYPE_BIND, EBPF_EXECUTION_JIT, EBPF_SUCCESS);

// Try to load bindmonitor with providing wrong program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", &EBPF_PROGRAM_TYPE_XDP, EBPF_EXECUTION_ANY, EBPF_VERIFICATION_FAILED);

// Try to load an unsafe program.
DECLARE_LOAD_TEST_CASE("droppacket_unsafe.o", nullptr, EBPF_EXECUTION_ANY, EBPF_VERIFICATION_FAILED);

TEST_CASE("test_ebpf_program_next_previous", "[test_ebpf_program_next_previous]")
{
    _test_program_next_previous("droppacket.o", DROP_PACKET_PROGRAM_COUNT);
    _test_program_next_previous("bindmonitor.o", BIND_MONITOR_PROGRAM_COUNT);
}

TEST_CASE("test_ebpf_map_next_previous", "[test_ebpf_map_next_previous]")
{
    _test_map_next_previous("droppacket.o", DROP_PACKET_MAP_COUNT);
    _test_map_next_previous("bindmonitor.o", BIND_MONITOR_MAP_COUNT);
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
    uint32_t ipv6_opt = 0;
    REQUIRE(
        setsockopt(_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_opt), sizeof(ULONG)) == 0);
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
    program_load_attach_helper_t _helper(
        "bindmonitor_ringbuf.o", EBPF_PROGRAM_TYPE_BIND, "bind_monitor", execution_type, nullptr, 0, hook);
    object = _helper.get_object();

    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    REQUIRE(process_map_fd > 0);

    // Create a list of fake app IDs and set it to event context.
    std::wstring app_id = L"api_test.exe";
    std::vector<std::vector<char>> app_ids;
    char* p = reinterpret_cast<char*>(&app_id[0]);
    std::vector<char> temp(p, p + (app_id.size() + 1) * sizeof(wchar_t));
    app_ids.push_back(temp);

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
    program_load_attach_helper_t _helper(
        "divide_by_zero.o", EBPF_PROGRAM_TYPE_BIND, "divide_by_zero", execution_type, nullptr, 0, hook);
    object = _helper.get_object();

    perform_socket_bind(0, false);

    // If we don't bug-check, the test passed.
}

TEST_CASE("ringbuf_api_jit", "[test_ringbuf_api]") { ring_buffer_api_test(EBPF_EXECUTION_JIT); }
TEST_CASE("divide_by_zero_jit", "[divide_by_zero]") { divide_by_zero_test_km(EBPF_EXECUTION_JIT); }

#if !defined(CONFIG_BPF_JIT_ALWAYS_ON)
TEST_CASE("ringbuf_api_interpret", "[test_ringbuf_api]") { ring_buffer_api_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("divide_by_zero_interpret", "[divide_by_zero]") { divide_by_zero_test_km(EBPF_EXECUTION_INTERPRET); }
#endif

int
perform_bind(SOCKET* socket, uint16_t port_number)
{
    *socket = INVALID_SOCKET;
    *socket = WSASocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, 0);
    REQUIRE(*socket != INVALID_SOCKET);
    SOCKADDR_STORAGE sock_addr;
    sock_addr.ss_family = AF_INET6;
    INETADDR_SETANY((PSOCKADDR)&sock_addr);

    // Perform bind operation.
    ((PSOCKADDR_IN6)&sock_addr)->sin6_port = htons(port_number);
    return (bind(*socket, (PSOCKADDR)&sock_addr, sizeof(sock_addr)));
}

void
bindmonitor_test(_In_ struct bpf_object* object)
{
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    REQUIRE(process_map_fd > 0);

    fd_t limits_map_fd = bpf_object__find_map_fd_by_name(object, "limits_map");
    REQUIRE(limits_map_fd > 0);

    // Set the limit to 2. Third bind from same app should fail.
    uint32_t key = 0;
    uint32_t value = 2;
    int error = bpf_map_update_elem(limits_map_fd, &key, &value, 0);
    REQUIRE(error == 0);

    WSAData data;
    SOCKET sockets[3];
    REQUIRE(WSAStartup(2, &data) == 0);

    // First and second binds should succeed.
    REQUIRE(perform_bind(&sockets[0], 30000) == 0);
    REQUIRE(perform_bind(&sockets[1], 30001) == 0);

    // Third bind from the same app should fail.
    REQUIRE(perform_bind(&sockets[2], 30002) != 0);

    WSACleanup();
}

TEST_CASE("bindmonitor_native_test", "[native_tests]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper(
        "bindmonitor_km.sys", EBPF_PROGRAM_TYPE_BIND, "BindMonitor", EBPF_EXECUTION_NATIVE, nullptr, 0, hook);
    object = _helper.get_object();

    bindmonitor_test(object);
}

TEST_CASE("bindmonitor_tailcall_native_test", "[native_tests]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper(
        "bindmonitor_tailcall_km.sys", EBPF_PROGRAM_TYPE_BIND, "BindMonitor", EBPF_EXECUTION_JIT, nullptr, 0, hook);
    object = _helper.get_object();

    // Setup tail calls.
    struct bpf_program* callee0 = bpf_object__find_program_by_name(object, "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(object, "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(object, "prog_array_map");
    REQUIRE(prog_map_fd > 0);

    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    bindmonitor_test(object);

    // Cleanup tail calls.
    index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
}
