// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "api_internal.h"
#include "api_test.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_structs.h"
#include "misc_helper.h"
#include "native_helper.hpp"
#include "program_helper.h"
#include "service_helper.h"
#include "socket_helper.h"
#include "watchdog.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <chrono>
#include <io.h>
#include <mstcpip.h>
#include <mutex>
#include <ntsecapi.h>
#include <thread>
#include <vector>

CATCH_REGISTER_LISTENER(_watchdog)

#define SAMPLE_PATH ""

#define EBPF_CORE_DRIVER_BINARY_NAME L"ebpfcore.sys"
#define EBPF_CORE_DRIVER_NAME L"ebpfcore"

#define EBPF_EXTENSION_DRIVER_BINARY_NAME L"netebpfext.sys"
#define EBPF_EXTENSION_DRIVER_NAME L"netebpfext"

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define EBPF_SERVICE_BINARY_NAME L"ebpfsvc.exe"
#define EBPF_SERVICE_NAME L"ebpfsvc"
#endif

#define DROP_PACKET_PROGRAM_COUNT 1
#define BIND_MONITOR_PROGRAM_COUNT 1

#define DROP_PACKET_MAP_COUNT 2
#define BIND_MONITOR_MAP_COUNT 3

#define WAIT_TIME_IN_MS 5000

typedef struct _audit_entry
{
    uint64_t logon_id;
    int32_t is_admin;
} audit_entry_t;

static service_install_helper
    _ebpf_core_driver_helper(EBPF_CORE_DRIVER_NAME, EBPF_CORE_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_extension_driver_helper(EBPF_EXTENSION_DRIVER_NAME, EBPF_EXTENSION_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
static service_install_helper
    _ebpf_service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME, SERVICE_WIN32_OWN_PROCESS);
#endif

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
    if (execution_type != EBPF_EXECUTION_NATIVE) {
        REQUIRE(strcmp(program_file_name, file_name) == 0);
    }

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

#if defined(CONFIG_BPF_JIT_DISABLED)
#define JIT_LOAD_RESULT -ENOTSUP
#else
#define JIT_LOAD_RESULT 0
#endif

#if defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define INTERPRET_LOAD_RESULT -ENOTSUP
#else
#define INTERPRET_LOAD_RESULT 0
#endif

static int32_t
_get_expected_jit_result(int32_t expected_result)
{
#if defined(CONFIG_BPF_JIT_DISABLED)
    UNREFERENCED_PARAMETER(expected_result);
    return -ENOTSUP;
#else
    return expected_result;
#endif
}

// Load droppacket (JIT) without providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);

DECLARE_LOAD_TEST_CASE("droppacket.sys", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, 0);

// Declare a duplicate test case. This will ensure that the earlier driver is actually unloaded,
// else this test case will fail.
DECLARE_DUPLICATE_LOAD_TEST_CASE("droppacket.sys", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, 2, 0);

// Load droppacket (ANY) without providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, JIT_LOAD_RESULT);

// Load droppacket (INTERPRET) without providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load droppacket with providing expected program type.
DECLARE_LOAD_TEST_CASE("droppacket.o", BPF_PROG_TYPE_XDP, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load bindmonitor (JIT) without providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);

// Load bindmonitor (INTERPRET) without providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load bindmonitor with providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_BIND, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);

// Try to load bindmonitor with providing wrong program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_XDP, EBPF_EXECUTION_ANY, _get_expected_jit_result(-EACCES));

// Try to load an unsafe program.
DECLARE_LOAD_TEST_CASE(
    "droppacket_unsafe.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, _get_expected_jit_result(-EACCES));

// Try to load multiple programs of different program types
TEST_CASE("test_ebpf_multiple_programs_load_jit")
{
    struct _ebpf_program_load_test_parameters test_parameters[] = {
        {"droppacket.o", BPF_PROG_TYPE_XDP}, {"bindmonitor.o", BPF_PROG_TYPE_BIND}};
    _test_multiple_programs_load(_countof(test_parameters), test_parameters, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);
}

TEST_CASE("test_ebpf_multiple_programs_load_interpret")
{
    struct _ebpf_program_load_test_parameters test_parameters[] = {
        {"droppacket.o", BPF_PROG_TYPE_XDP}, {"bindmonitor.o", BPF_PROG_TYPE_BIND}};
    _test_multiple_programs_load(
        _countof(test_parameters), test_parameters, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("test_ebpf_program_next_previous_jit", "[test_ebpf_program_next_previous]")
{
    _test_program_next_previous("droppacket.o", DROP_PACKET_PROGRAM_COUNT);
    _test_program_next_previous("bindmonitor.o", BIND_MONITOR_PROGRAM_COUNT);
}

TEST_CASE("test_ebpf_map_next_previous_jit", "[test_ebpf_map_next_previous]")
{
    _test_map_next_previous("droppacket.o", DROP_PACKET_MAP_COUNT);
    _test_map_next_previous("bindmonitor.o", BIND_MONITOR_MAP_COUNT);
}
#endif

TEST_CASE("test_ebpf_program_next_previous_native", "[test_ebpf_program_next_previous]")
{
    native_module_helper_t droppacket_helper;
    droppacket_helper.initialize("droppacket", EBPF_EXECUTION_NATIVE);
    _test_program_next_previous(droppacket_helper.get_file_name().c_str(), DROP_PACKET_PROGRAM_COUNT);

    native_module_helper_t bindmonitor_helper;
    bindmonitor_helper.initialize("bindmonitor", EBPF_EXECUTION_NATIVE);
    _test_program_next_previous(bindmonitor_helper.get_file_name().c_str(), BIND_MONITOR_PROGRAM_COUNT);
}

TEST_CASE("test_ebpf_map_next_previous_native", "[test_ebpf_map_next_previous]")
{
    native_module_helper_t droppacket_helper;
    droppacket_helper.initialize("droppacket", EBPF_EXECUTION_NATIVE);
    _test_map_next_previous(droppacket_helper.get_file_name().c_str(), DROP_PACKET_MAP_COUNT);

    native_module_helper_t bindmonitor_helper;
    bindmonitor_helper.initialize("bindmonitor", EBPF_EXECUTION_NATIVE);
    _test_map_next_previous(bindmonitor_helper.get_file_name().c_str(), BIND_MONITOR_MAP_COUNT);
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
    program_load_attach_helper_t _helper;
    _helper.initialize("divide_by_zero.o", BPF_PROG_TYPE_BIND, "divide_by_zero", execution_type, nullptr, 0, hook);
    object = _helper.get_object();

    perform_socket_bind(0, true);

    // If we don't bug-check, the test passed.
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("ringbuf_api_jit", "[test_ringbuf_api]") { ring_buffer_api_test(EBPF_EXECUTION_JIT); }
TEST_CASE("divide_by_zero_jit", "[divide_by_zero]") { divide_by_zero_test_km(EBPF_EXECUTION_JIT); }
#endif

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("ringbuf_api_interpret", "[test_ringbuf_api]") { ring_buffer_api_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("divide_by_zero_interpret", "[divide_by_zero]") { divide_by_zero_test_km(EBPF_EXECUTION_INTERPRET); }
#endif

void
_test_nested_maps(bpf_map_type type)
{
    // Create first inner map.
    fd_t inner_map_fd1 =
        bpf_map_create(BPF_MAP_TYPE_ARRAY, "inner_map1", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(inner_map_fd1 > 0);

    // Create outer map.
    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd1};
    fd_t outer_map_fd = bpf_map_create(type, "outer_map", sizeof(uint32_t), sizeof(fd_t), 10, &opts);
    REQUIRE(outer_map_fd > 0);

    // Create second inner map.
    fd_t inner_map_fd2 =
        bpf_map_create(BPF_MAP_TYPE_ARRAY, "inner_map2", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(inner_map_fd2 > 0);

    // Insert both inner maps in outer map.
    uint32_t key = 1;
    uint32_t result = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd1, 0);
    REQUIRE(result == ERROR_SUCCESS);

    key = 2;
    result = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd2, 0);
    REQUIRE(result == ERROR_SUCCESS);

    // Add inner map (1) multiple times.
    key = 3;
    result = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd1, 0);
    REQUIRE(result == ERROR_SUCCESS);

    key = 4;
    result = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd1, 0);
    REQUIRE(result == ERROR_SUCCESS);

    // Add inner map (2) multiple times.
    key = 5;
    result = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd2, 0);
    REQUIRE(result == ERROR_SUCCESS);

    key = 6;
    result = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd2, 0);
    REQUIRE(result == ERROR_SUCCESS);

    key = 7;
    result = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd2, 0);
    REQUIRE(result == ERROR_SUCCESS);

    // Remove some inner maps from outer map.
    key = 1;
    result = bpf_map_delete_elem(outer_map_fd, &key);
    REQUIRE(result == ERROR_SUCCESS);

    key = 2;
    result = bpf_map_delete_elem(outer_map_fd, &key);
    REQUIRE(result == ERROR_SUCCESS);

    // Leave the other instances of 'map inserts' as-is, the post-app-termination clean-up should take care of these.

    _close(inner_map_fd1);
    _close(inner_map_fd2);
    _close(outer_map_fd);
}

TEST_CASE("array_map_of_maps", "[map_in_map]") { _test_nested_maps(BPF_MAP_TYPE_ARRAY_OF_MAPS); }
TEST_CASE("hash_map_of_maps", "[map_in_map]") { _test_nested_maps(BPF_MAP_TYPE_HASH_OF_MAPS); }

void
tailcall_load_test(_In_z_ const char* file_name)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;

    result = _program_load_helper(file_name, BPF_PROG_TYPE_XDP, EBPF_EXECUTION_ANY, &object, &program_fd);
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

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("tailcall_load_test_jit", "[tailcall_load_test]") { tailcall_load_test("tail_call_multiple.o"); }
#endif

TEST_CASE("tailcall_load_test_native", "[tailcall_load_test]") { tailcall_load_test("tail_call_multiple.sys"); }

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
    program_load_attach_helper_t _helper;
    _helper.initialize("bindmonitor.sys", BPF_PROG_TYPE_BIND, "BindMonitor", EBPF_EXECUTION_NATIVE, nullptr, 0, hook);
    object = _helper.get_object();

    bindmonitor_test(object);
}

TEST_CASE("bindmonitor_tailcall_native_test", "[native_tests]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper;
    _helper.initialize(
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
    if (outer_map == nullptr) {
        cleanup();
    }
    REQUIRE(outer_map != nullptr);

    int outer_map_fd = bpf_map__fd(outer_map);
    if (outer_map_fd <= 0) {
        cleanup();
    }
    REQUIRE(outer_map_fd > 0);

    // Test map-in-maps.
    struct bpf_map* outer_idx_map = bpf_object__find_map_by_name(object, "dummy_outer_idx_map");
    if (outer_idx_map == nullptr) {
        cleanup();
    }
    REQUIRE(outer_idx_map != nullptr);

    int outer_idx_map_fd = bpf_map__fd(outer_idx_map);
    if (outer_idx_map_fd <= 0) {
        cleanup();
    }
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
    program_load_attach_helper_t _helper;
    _helper.initialize(
        "pidtgid.sys", BPF_PROG_TYPE_BIND, program_name, EBPF_EXECUTION_NATIVE, &ifindex, sizeof(ifindex), hook);
    struct bpf_object* object = _helper.get_object();

    // Bind a socket.
    WSAData data;
    REQUIRE(WSAStartup(2, &data) == 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

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
    unsigned long pid = GetCurrentProcessId();
    unsigned long tid = GetCurrentThreadId();
    REQUIRE(pid == value.context_pid);
    REQUIRE(pid == value.current_pid);
    REQUIRE(tid == value.current_tid);

    // Clean up.
    WSACleanup();
}

TEST_CASE("native_module_handle_test", "[native_tests]")
{
    int result;
    const char* file_name = "bindmonitor.sys";
    struct bpf_object* object = nullptr;
    struct bpf_object* object2 = nullptr;
    fd_t program_fd;

    result = _program_load_helper(file_name, BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(program_fd != ebpf_fd_invalid);

    fd_t native_module_fd = object->native_module_fd;
    REQUIRE(native_module_fd != ebpf_fd_invalid);

    // Bindmonitor has 2 maps and 1 program. Fetch and close all these fds.
    bpf_map* map1 = bpf_object__find_map_by_name(object, "process_map");
    REQUIRE(map1 != nullptr);
    REQUIRE(map1->map_fd != ebpf_fd_invalid);
    bpf_map* map2 = bpf_object__find_map_by_name(object, "limits_map");
    REQUIRE(map2 != nullptr);
    REQUIRE(map2->map_fd != ebpf_fd_invalid);
    bpf_program* program = bpf_object__find_program_by_name(object, "BindMonitor");
    REQUIRE(program != nullptr);
    REQUIRE(program->fd != ebpf_fd_invalid);

    _close(map1->map_fd);
    _close(map2->map_fd);
    _close(program->fd);

    // Set the above closed FDs to ebpf_fd_invalid to avoid double close of FDs.
    map1->map_fd = ebpf_fd_invalid;
    map2->map_fd = ebpf_fd_invalid;
    program->fd = ebpf_fd_invalid;

    // Try to load the same native module again, which should fail.
    result = _program_load_helper(file_name, BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object2, &program_fd);
    REQUIRE(result == -ENOENT);

    // Close the native module handle. That should result in the module to be unloaded.
    REQUIRE(_close(native_module_fd) == 0);
    object->native_module_fd = ebpf_fd_invalid;

    // Add a sleep to allow the previous driver to be unloaded successfully.
    Sleep(1000);

    // Try to load the same native module again. It should succeed this time.
    object2 = nullptr;
    result = _program_load_helper(file_name, BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object2, &program_fd);
    REQUIRE(result == 0);

    bpf_object__close(object);
    bpf_object__close(object2);
}

TEST_CASE("nomap_load_test", "[native_tests]")
{
    // This test case tests loading of native ebpf programs that do not contain/refer-to any map.
    // This test should succeed as this is a valid use case.
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper;
    _helper.initialize("printk.sys", BPF_PROG_TYPE_BIND, "func", EBPF_EXECUTION_NATIVE, nullptr, 0, hook);
    auto object = _helper.get_object();
    REQUIRE(object != nullptr);
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

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("bpf_user_helpers_test_jit", "[api_test]") { bpf_user_helpers_test(EBPF_EXECUTION_JIT); }
#endif
TEST_CASE("bpf_user_helpers_test_native", "[api_test]") { bpf_user_helpers_test(EBPF_EXECUTION_NATIVE); }

// This test tests resource reclamation and clean-up after a premature/abnormal user mode application exit.
TEST_CASE("close_unload_test", "[native_tests][native_close_cleanup_tests]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper;
    _helper.initialize(
        "bindmonitor_tailcall.sys", BPF_PROG_TYPE_BIND, "BindMonitor", EBPF_EXECUTION_NATIVE, nullptr, 0, hook);
    object = _helper.get_object();

    // Set up tail calls.
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

    // Now insert the same program for multiple keys in the same map.
    index = 2;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    index = 4;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    index = 7;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    bindmonitor_test(object);

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
    // stop the ebpf-core driver after executing this class of tests.  If the clean-up by the ebpf-core driver is not
    // successful, it cannot be stopped/unloaded.  This step is performed automatically by the CI/CD test pass runs and
    // will need to be perfomed as an explicit manual step after a manually initiated test-run.
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

void
test_sock_addr_native_program_load_attach(const char* file_name)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    uint32_t next_id;
    std::string file_name_string = std::string("regression\\") + std::string(file_name);
    const char* file_name_with_path = file_name_string.c_str();

    result = _program_load_helper(file_name_with_path, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == 0);

    bpf_program* v4_program = bpf_object__find_program_by_name(object, "connect_redirect4");
    REQUIRE(v4_program != nullptr);

    bpf_program* v6_program = bpf_object__find_program_by_name(object, "connect_redirect6");
    REQUIRE(v6_program != nullptr);

    // Attach both v4 and v6 programs.
    bpf_link* v4_link = bpf_program__attach(v4_program);
    REQUIRE(v4_link != nullptr);

    bpf_link* v6_link = bpf_program__attach(v6_program);
    REQUIRE(v6_link != nullptr);

    // Detach both v4 and v6 programs.
    result = bpf_link__destroy(v4_link);
    REQUIRE(result == 0);

    result = bpf_link__destroy(v6_link);
    REQUIRE(result == 0);

    bpf_object__close(object);

    // We have closed handles to the programs. Program should be unloaded now.
    REQUIRE(bpf_prog_get_next_id(0, &next_id) == -ENOENT);
}

#define DECLARE_REGRESSION_TEST_CASE(version)                                                         \
    TEST_CASE("test_native_program_load_attach-regression-" #version)                                 \
    {                                                                                                 \
        test_sock_addr_native_program_load_attach((const char*)"cgroup_sock_addr2_"##version ".sys"); \
    }

DECLARE_REGRESSION_TEST_CASE("0.9.0")

// The below tests try to load native drivers for invalid programs (that will fail verification).
// Since verification can be skipped in bpf2c for only Debug builds, these tests are applicable
// only for Debug build.
#ifdef _DEBUG

static void
_load_invalid_program(_In_z_ const char* file_name, ebpf_execution_type_t execution_type, int expected_result)
{
    int result;
    bpf_object* object = nullptr;
    fd_t program_fd;
    uint32_t next_id;

    result = _program_load_helper(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &object, &program_fd);
    REQUIRE(result == expected_result);

    if (result != 0) {
        // If load failed, no programs or maps should be loaded.
        REQUIRE(bpf_map_get_next_id(0, &next_id) == -ENOENT);
        REQUIRE(bpf_prog_get_next_id(0, &next_id) == -ENOENT);
    }
}

TEST_CASE("load_native_program_invalid1", "[native][negative]")
{
    _load_invalid_program("invalid_maps1.sys", EBPF_EXECUTION_NATIVE, -EINVAL);
}
TEST_CASE("load_native_program_invalid2", "[native][negative]")
{
    _load_invalid_program("invalid_maps2.sys", EBPF_EXECUTION_NATIVE, -EINVAL);
}
TEST_CASE("load_native_program_invalid3", "[native][negative]")
{
    _load_invalid_program("invalid_helpers.sys", EBPF_EXECUTION_NATIVE, -EINVAL);
}
TEST_CASE("load_native_program_invalid4", "[native][negative]")
{
    _load_invalid_program("empty.sys", EBPF_EXECUTION_NATIVE, -EINVAL);
}
TEST_CASE("load_native_program_invalid5", "[native][negative]")
{
    _load_invalid_program("invalid_maps3.sys", EBPF_EXECUTION_NATIVE, -EINVAL);
}

#endif