// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <mutex>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#include "api_test.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_structs.h"
#include <io.h>
#include "program_helper.h"
#include "service_helper.h"
#include "socket_helper.h"
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

#define WAIT_TIME_IN_MS 5000

static service_install_helper
    _ebpf_core_driver_helper(EBPF_CORE_DRIVER_NAME, EBPF_CORE_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_extension_driver_helper(EBPF_EXTENSION_DRIVER_NAME, EBPF_EXTENSION_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME, SERVICE_WIN32_OWN_PROCESS);

static int
_program_load_helper(
    const char* file_name,
    bpf_prog_type prog_type,
    ebpf_execution_type_t execution_type,
    struct bpf_object** object,
    fd_t* program_fd)
{
    struct bpf_object* new_object = bpf_object__open(file_name);
    if (new_object == nullptr) {
        return EBPF_FAILED;
    }

    REQUIRE(ebpf_object_set_execution_type(new_object, execution_type) == EBPF_SUCCESS);

    struct bpf_program* program = bpf_object__next_program(new_object, nullptr);

    if (prog_type != BPF_PROG_TYPE_UNSPEC) {
        bpf_program__set_type(program, prog_type);
    }

    int error = bpf_object__load(new_object);
    if (error < 0) {
        bpf_object__close(new_object);
        return error;
    }

    *program_fd = bpf_program__fd(program);
    *object = new_object;
    return 0;
}

static void
_test_program_load(
    const char* file_name, bpf_prog_type program_type, ebpf_execution_type_t execution_type, int expected_load_result)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;

    result = _program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
    REQUIRE(result == expected_load_result);

    if (expected_load_result == 0) {
        REQUIRE(program_fd > 0);
    } else {
        return;
    }

    uint32_t next_id;
    REQUIRE(bpf_prog_get_next_id(0, &next_id) == 0);

    // Query loaded programs to verify this program is loaded.
    program_fd = bpf_prog_get_fd_by_id(next_id);
    REQUIRE(program_fd > 0);

    const char* program_file_name;
    const char* program_section_name;
    ebpf_execution_type_t program_execution_type;
    REQUIRE(
        ebpf_program_query_info(program_fd, &program_execution_type, &program_file_name, &program_section_name) ==
        EBPF_SUCCESS);
    _close(program_fd);

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
    uint32_t previous_id = next_id;
    REQUIRE(bpf_prog_get_next_id(previous_id, &next_id) == -ENOENT);

    bpf_object__close(object);

    // We have closed both handles to the program. Program should be unloaded now.
    REQUIRE(bpf_prog_get_next_id(0, &next_id) == -ENOENT);
}

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

        result = _program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
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

static void
_test_map_next_previous(const char* file_name, int expected_map_count)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int map_count = 0;
    struct bpf_map* previous = nullptr;
    struct bpf_map* next = nullptr;
    result = _program_load_helper(file_name, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == 0);

    next = bpf_object__next_map(object, previous);
    while (next != nullptr) {
        map_count++;
        previous = next;
        next = bpf_object__next_map(object, previous);
    }
    REQUIRE(map_count == expected_map_count);

    map_count = 0;
    previous = next = nullptr;

    previous = bpf_object__prev_map(object, next);
    while (previous != nullptr) {
        map_count++;
        next = previous;
        previous = bpf_object__prev_map(object, next);
    }
    REQUIRE(map_count == expected_map_count);

    bpf_object__close(object);
}

static void
_test_program_next_previous(const char* file_name, int expected_program_count)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int program_count = 0;
    struct bpf_program* previous = nullptr;
    struct bpf_program* next = nullptr;
    result = _program_load_helper(file_name, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == 0);

    next = bpf_object__next_program(object, previous);
    while (next != nullptr) {
        program_count++;
        previous = next;
        next = bpf_object__next_program(object, previous);
    }
    REQUIRE(program_count == expected_program_count);

    program_count = 0;
    previous = next = nullptr;

    previous = bpf_object__prev_program(object, next);
    while (previous != nullptr) {
        program_count++;
        next = previous;
        previous = bpf_object__prev_program(object, next);
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

// Duplicate tests sleep for WAIT_TIME_IN_MS seconds. This ensures the previous driver is
// unloaded by the time the test is re-run.
#define DECLARE_DUPLICATE_LOAD_TEST_CASE(file, program_type, execution_type, instance, expected_result) \
    TEST_CASE("test_ebpf_program_load-" #file "-" #program_type "-" #execution_type "-" #instance)      \
    {                                                                                                   \
        Sleep(WAIT_TIME_IN_MS);                                                                         \
        _test_program_load(file, program_type, execution_type, expected_result);                        \
    }

#if defined(CONFIG_BPF_JIT_ALWAYS_ON)
#define INTERPRET_LOAD_RESULT -EOTHER
#else
#define INTERPRET_LOAD_RESULT 0
#endif

// Load droppacket (JIT) without providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT, 0);

DECLARE_LOAD_TEST_CASE("droppacket.sys", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, 0);

// Declare a duplicate test case. This will ensure that the earlier driver is actually unloaded,
// else this test case will fail.
DECLARE_DUPLICATE_LOAD_TEST_CASE("droppacket.sys", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, 2, 0);

// Load droppacket (ANY) without providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, 0);

// Load droppacket (INTERPRET) without providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load droppacket with providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", BPF_PROG_TYPE_XDP, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load bindmonitor (JIT) without providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT, 0);

// Load bindmonitor (INTERPRET) without providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load bindmonitor with providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_BIND, EBPF_EXECUTION_JIT, 0);

// Try to load bindmonitor with providing wrong program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_XDP, EBPF_EXECUTION_ANY, -EACCES);

// Try to load an unsafe program.
DECLARE_LOAD_TEST_CASE("droppacket_unsafe.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, -EACCES);

// Try to load multiple programs of different program types
TEST_CASE("test_ebpf_multiple_programs_load_jit")
{
    struct _ebpf_program_load_test_parameters test_parameters[] = {
        {"droppacket.o", BPF_PROG_TYPE_XDP}, {"bindmonitor.o", BPF_PROG_TYPE_BIND}};
    _test_multiple_programs_load(_countof(test_parameters), test_parameters, EBPF_EXECUTION_JIT, 0);
}

TEST_CASE("test_ebpf_multiple_programs_load_interpret")
{
    struct _ebpf_program_load_test_parameters test_parameters[] = {
        {"droppacket.o", BPF_PROG_TYPE_XDP}, {"bindmonitor.o", BPF_PROG_TYPE_BIND}};
    _test_multiple_programs_load(
        _countof(test_parameters), test_parameters, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);
}

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
    uint32_t ipv6_option = 0;
    REQUIRE(
        setsockopt(_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_option), sizeof(ULONG)) ==
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
    program_load_attach_helper_t _helper(
        "bindmonitor_ringbuf.o", BPF_PROG_TYPE_BIND, "bind_monitor", execution_type, nullptr, 0, hook);
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
        "divide_by_zero.o", BPF_PROG_TYPE_BIND, "divide_by_zero", execution_type, nullptr, 0, hook);
    object = _helper.get_object();

    perform_socket_bind(0, true);

    // If we don't bug-check, the test passed.
}

TEST_CASE("ringbuf_api_jit", "[test_ringbuf_api]") { ring_buffer_api_test(EBPF_EXECUTION_JIT); }
TEST_CASE("divide_by_zero_jit", "[divide_by_zero]") { divide_by_zero_test_km(EBPF_EXECUTION_JIT); }

#if !defined(CONFIG_BPF_JIT_ALWAYS_ON)
TEST_CASE("ringbuf_api_interpret", "[test_ringbuf_api]") { ring_buffer_api_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("divide_by_zero_interpret", "[divide_by_zero]") { divide_by_zero_test_km(EBPF_EXECUTION_INTERPRET); }
#endif

void
_test_nested_maps(bpf_map_type type)
{
    // Create first inner map.
    fd_t inner1 = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(inner1 > 0);

    // Create outer map.
    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner1};
    fd_t outer_map_fd = bpf_map_create(type, "outer_map", sizeof(uint32_t), sizeof(fd_t), 10, &opts);

    REQUIRE(outer_map_fd > 0);

    // Create second inner map.
    fd_t inner2 = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(inner2 > 0);

    // Insert both inner maps in outer map.
    uint32_t key = 1;
    uint32_t result = bpf_map_update_elem(outer_map_fd, &key, &inner1, 0);
    REQUIRE(result == ERROR_SUCCESS);

    key = 2;
    result = bpf_map_update_elem(outer_map_fd, &key, &inner1, 0);
    REQUIRE(result == ERROR_SUCCESS);

    // Remove the inner maps from outer map.
    key = 1;
    result = bpf_map_delete_elem(outer_map_fd, &key);
    REQUIRE(result == ERROR_SUCCESS);
    key = 2;
    result = bpf_map_delete_elem(outer_map_fd, &key);
    REQUIRE(result == ERROR_SUCCESS);

    _close(inner1);
    _close(inner2);
    _close(outer_map_fd);
}

TEST_CASE("array_of_maps", "[map_in_map]") { _test_nested_maps(BPF_MAP_TYPE_ARRAY_OF_MAPS); }

TEST_CASE("hash_of_maps", "[map_in_map]") { _test_nested_maps(BPF_MAP_TYPE_HASH_OF_MAPS); }

TEST_CASE("tailcall_load_test", "[tailcall_load_test]")
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;

    result = _program_load_helper("tail_call_multiple.o", BPF_PROG_TYPE_XDP, EBPF_EXECUTION_ANY, &object, &program_fd);
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
    REQUIRE(bpf_program__get_type(callee0) == BPF_PROG_TYPE_XDP);

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

int
perform_bind(_Out_ SOCKET* socket, uint16_t port_number)
{
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
        "bindmonitor.sys", BPF_PROG_TYPE_BIND, "BindMonitor", EBPF_EXECUTION_NATIVE, nullptr, 0, hook);
    object = _helper.get_object();

    bindmonitor_test(object);
}

TEST_CASE("bindmonitor_tailcall_native_test", "[native_tests]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper(
        "bindmonitor_tailcall.sys", BPF_PROG_TYPE_BIND, "BindMonitor", EBPF_EXECUTION_NATIVE, nullptr, 0, hook);
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

    auto cleanup = [prog_map_fd, &index]() {
        index = 0;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
        index = 1;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    };

    // Test map-in-maps.
    struct bpf_map* outer_map = bpf_object__find_map_by_name(object, "dummy_outer_map");
    if (outer_map == nullptr)
        cleanup();
    REQUIRE(outer_map != nullptr);

    int outer_map_fd = bpf_map__fd(outer_map);
    if (outer_map_fd <= 0)
        cleanup();
    REQUIRE(outer_map_fd > 0);

    // Test map-in-maps.
    struct bpf_map* outer_idx_map = bpf_object__find_map_by_name(object, "dummy_outer_idx_map");
    if (outer_idx_map == nullptr)
        cleanup();
    REQUIRE(outer_idx_map != nullptr);

    int outer_idx_map_fd = bpf_map__fd(outer_idx_map);
    if (outer_idx_map_fd <= 0)
        cleanup();
    REQUIRE(outer_idx_map_fd > 0);

    // Clean up tail calls.
    cleanup();
}

#define SOCKET_TEST_PORT 0x3bbf

TEST_CASE("bpf_get_current_pid_tgid", "[helpers]")
{
    // Load and attach ebpf program.
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    uint32_t ifindex = 0;
    const char* program_name = "func";
    program_load_attach_helper_t _helper(
        "pidtgid.sys", BPF_PROG_TYPE_BIND, program_name, EBPF_EXECUTION_NATIVE, &ifindex, sizeof(ifindex), hook);
    struct bpf_object* object = _helper.get_object();

    // Bind a socket.
    WSAData data;
    REQUIRE(WSAStartup(2, &data) == 0);
    datagram_receiver_socket_t datagram_receiver_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    // Read from map.
    struct bpf_map* map = bpf_object__find_map_by_name(object, "pidtgid_map");
    REQUIRE(map != nullptr);
    uint32_t key = 0;
    struct value
    {
        uint32_t context_pid;
        uint32_t current_pid;
        uint32_t current_tid;
    } value;
    REQUIRE(bpf_map_lookup_elem(bpf_map__fd(map), &key, &value) == 0);

    // Verify PID/TID values.
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    REQUIRE(pid == value.context_pid);
    REQUIRE(pid == value.current_pid);
    REQUIRE(tid == value.current_tid);

    // Clean up.
    WSACleanup();
}
