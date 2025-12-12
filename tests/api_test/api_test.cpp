// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "api_internal.h"
#include "api_test.h"
#include "api_test_jit.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_ring_buffer_record.h"
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
#include <iomanip>
#include <lsalookup.h>
#include <mstcpip.h>
#include <mutex>
#define _NTDEF_ // UNICODE_STRING is already defined
#include <ntsecapi.h>
#include <processthreadsapi.h>
#include <thread>
#include <vector>
using namespace std::chrono_literals;

CATCH_REGISTER_LISTENER(_watchdog)

#define SAMPLE_PATH ""

#define EBPF_CORE_DRIVER_BINARY_NAME L"ebpfcore.sys"
#define EBPF_CORE_DRIVER_NAME L"ebpfcore"

#define EBPF_EXTENSION_DRIVER_BINARY_NAME L"netebpfext.sys"
#define EBPF_EXTENSION_DRIVER_NAME L"netebpfext"

#define WAIT_TIME_IN_MS 5000

static service_install_helper
    _ebpf_core_driver_helper(EBPF_CORE_DRIVER_NAME, EBPF_CORE_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static service_install_helper
    _ebpf_extension_driver_helper(EBPF_EXTENSION_DRIVER_NAME, EBPF_EXTENSION_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

static void
_test_program_load(
    const char* file_name, bpf_prog_type program_type, ebpf_execution_type_t execution_type, int expected_load_result)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;

    result = program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
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

        result = program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
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

TEST_CASE("pinned_map_enum", "[pinned_map_enum]") { ebpf_test_pinned_map_enum(true); }

// Test without verifying literal pin path value.
// This test can be used in regression tests even if
// the pin path syntax changes.
TEST_CASE("pinned_map_enum2", "[pinned_map_enum]") { ebpf_test_pinned_map_enum(false); }

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

#if defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define INTERPRET_LOAD_RESULT -ENOTSUP
#else
#define INTERPRET_LOAD_RESULT 0
#endif

// Load test_sample_ebpf (JIT) without providing expected program type.
DECLARE_LOAD_TEST_CASE("test_sample_ebpf.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);

DECLARE_LOAD_TEST_CASE("test_sample_ebpf.sys", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, 0);

// Declare a duplicate test case. This will ensure that the earlier driver is actually unloaded,
// else this test case will fail.
DECLARE_DUPLICATE_LOAD_TEST_CASE("test_sample_ebpf.sys", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, 2, 0);

// Load test_sample_ebpf (ANY) without providing expected program type.
DECLARE_LOAD_TEST_CASE("test_sample_ebpf.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, JIT_LOAD_RESULT);

// Load test_sample_ebpf (INTERPRET) without providing expected program type.
DECLARE_LOAD_TEST_CASE("test_sample_ebpf.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load test_sample_ebpf with providing expected program type.
DECLARE_LOAD_TEST_CASE("test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load bindmonitor (JIT) without providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);

// Load bindmonitor (INTERPRET) without providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);

// Load bindmonitor with providing expected program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_BIND, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);

// Try to load bindmonitor with providing wrong program type.
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_ANY, get_expected_jit_result(-EACCES));

// Try to load an unsafe program.
DECLARE_LOAD_TEST_CASE("printk_unsafe.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, get_expected_jit_result(-EACCES));

// Try to load multiple programs of different program types
TEST_CASE("test_ebpf_multiple_programs_load_jit")
{
    struct _ebpf_program_load_test_parameters test_parameters[] = {
        {"test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE}, {"bindmonitor.o", BPF_PROG_TYPE_BIND}};
    _test_multiple_programs_load(_countof(test_parameters), test_parameters, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);
}

TEST_CASE("test_ebpf_multiple_programs_load_interpret")
{
    struct _ebpf_program_load_test_parameters test_parameters[] = {
        {"test_sample_ebpf.o", BPF_PROG_TYPE_SAMPLE}, {"bindmonitor.o", BPF_PROG_TYPE_BIND}};
    _test_multiple_programs_load(
        _countof(test_parameters), test_parameters, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);
}

TEST_CASE("test_ebpf_program_next_previous_native", "[test_ebpf_program_next_previous]")
{
    native_module_helper_t test_sample_ebpf_helper;
    test_sample_ebpf_helper.initialize("test_sample_ebpf", EBPF_EXECUTION_NATIVE);
    test_program_next_previous(test_sample_ebpf_helper.get_file_name().c_str(), SAMPLE_PROGRAM_COUNT);

    native_module_helper_t bindmonitor_helper;
    bindmonitor_helper.initialize("bindmonitor", EBPF_EXECUTION_NATIVE);
    test_program_next_previous(bindmonitor_helper.get_file_name().c_str(), BIND_MONITOR_PROGRAM_COUNT);
}

TEST_CASE("test_ebpf_map_next_previous_native", "[test_ebpf_map_next_previous]")
{
    native_module_helper_t test_sample_ebpf_helper;
    test_sample_ebpf_helper.initialize("test_sample_ebpf", EBPF_EXECUTION_NATIVE);
    test_map_next_previous(test_sample_ebpf_helper.get_file_name().c_str(), SAMPLE_MAP_COUNT);

    native_module_helper_t bindmonitor_helper;
    bindmonitor_helper.initialize("bindmonitor", EBPF_EXECUTION_NATIVE);
    test_map_next_previous(bindmonitor_helper.get_file_name().c_str(), BIND_MONITOR_MAP_COUNT);
}

TEST_CASE("ring_buffer_mmap_consumer", "[ring_buffer]")
{
    // Create a ring buffer map for testing.
    fd_t map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "test_ringbuf", 0, 0, 64 * 1024, nullptr);
    REQUIRE(map_fd > 0);

    // Create wait handle for notifications.
    HANDLE wait_handle = CreateEvent(nullptr, false, false, nullptr);
    REQUIRE(wait_handle != NULL);

    // Set map wait handle.
    ebpf_result result = ebpf_map_set_wait_handle(map_fd, 0, (ebpf_handle_t)wait_handle);
    REQUIRE(result == EBPF_SUCCESS);

    // Get pointers to the mapped memory regions.
    const volatile LONG64* producer_ptr = nullptr;
    volatile LONG64* consumer_ptr = nullptr;
    const uint8_t* data = nullptr;
    size_t data_size = 0;

    result =
        ebpf_ring_buffer_map_map_buffer(map_fd, (void**)&consumer_ptr, (const void**)&producer_ptr, &data, &data_size);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(producer_ptr != nullptr);
    REQUIRE(consumer_ptr != nullptr);
    REQUIRE(data != nullptr);

    // Initialize offsets.
    uint64_t producer_offset = ReadAcquire64(producer_ptr);
    uint64_t consumer_offset = ReadNoFence64(consumer_ptr);
    bool have_data = producer_offset > consumer_offset;
    REQUIRE(have_data == false);

    // Write some test data to the ring buffer.
    std::string test_data = "Hello, Ring Buffer!";
    result = ebpf_ring_buffer_map_write(map_fd, test_data.c_str(), test_data.length());
    REQUIRE(result == EBPF_SUCCESS);

    // Write another test record.
    std::string test_data2 = "Second record";
    result = ebpf_ring_buffer_map_write(map_fd, test_data2.c_str(), test_data2.length());
    REQUIRE(result == EBPF_SUCCESS);

    // Update producer offset after writing.
    producer_offset = ReadAcquire64(producer_ptr);
    have_data = producer_offset > consumer_offset;
    REQUIRE(have_data == true);

    // Wait for notification.
    DWORD wait_status = WaitForSingleObject(wait_handle, 1000);
    REQUIRE(wait_status == WAIT_OBJECT_0);

    // Consumer loop to read records.
    uint32_t records_read = 0;
    const uint32_t expected_records = 2;
    std::vector<std::string> received_data;

    while (records_read < expected_records) {
        uint64_t remaining = producer_offset - consumer_offset;

        // Check for empty ring.
        if (remaining == 0) {
            break;
        }

        REQUIRE(remaining > EBPF_RINGBUF_HEADER_SIZE);

        // Get the next record.
        const ebpf_ring_buffer_record_t* record =
            ebpf_ring_buffer_next_record(data, data_size, consumer_offset, producer_offset);
        REQUIRE(record != nullptr);

        uint32_t record_length = ebpf_ring_buffer_record_length(record);
        REQUIRE(record_length > 0);

        // Read data from record.
        std::string record_data(reinterpret_cast<const char*>(record->data), record_length);
        received_data.push_back(record_data);
        records_read++;

        // Update consumer offset.
        consumer_offset += ebpf_ring_buffer_record_total_size(record);
        WriteNoFence64(consumer_ptr, consumer_offset);

        // Update producer offset for next iteration.
        producer_offset = ReadAcquire64(producer_ptr);
    }

    // Verify we read the expected records.
    REQUIRE(records_read == expected_records);
    REQUIRE(received_data.size() == expected_records);
    REQUIRE(received_data[0] == test_data);
    REQUIRE(received_data[1] == test_data2);

    // Clean up.
    REQUIRE(
        ebpf_ring_buffer_map_unmap_buffer(map_fd, (void*)consumer_ptr, (void*)producer_ptr, (void*)data) ==
        EBPF_SUCCESS);
    CloseHandle(wait_handle);
    _close(map_fd);
}

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

TEST_CASE("duplicate_fd", "")
{
    _disable_crt_report_hook disable_hook;

    fd_t map_fd1 = bpf_map_create(BPF_MAP_TYPE_ARRAY, "map", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(map_fd1 > 0);

    uint32_t key = 0;
    uint32_t value = 1;
    REQUIRE(bpf_map_update_elem(map_fd1, &key, &value, 0) == 0);

    fd_t map_fd2;
    REQUIRE(ebpf_duplicate_fd(map_fd1, &map_fd2) == EBPF_SUCCESS);
    REQUIRE(map_fd2 > 0);

    REQUIRE(bpf_map_lookup_elem(map_fd2, &key, &value) == 0);
    REQUIRE(value == 1);

    REQUIRE(ebpf_close_fd(map_fd2) == EBPF_SUCCESS);
    REQUIRE(ebpf_close_fd(map_fd2) == EBPF_FAILED);
    REQUIRE(bpf_map_lookup_elem(map_fd2, &key, &value) == -EBADF);
    REQUIRE(bpf_map_lookup_elem(map_fd1, &key, &value) == 0);

    REQUIRE(ebpf_close_fd(map_fd1) == EBPF_SUCCESS);
}

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
    native_module_helper_t _native_helper;
    _native_helper.initialize("bindmonitor", EBPF_EXECUTION_NATIVE);
    _helper.initialize(
        _native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        "BindMonitor",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);
    object = _helper.get_object();

    bindmonitor_test(object);
}

TEST_CASE("bindmonitor_tailcall_native_test", "[native_tests]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper;
    native_module_helper_t _native_helper;
    _native_helper.initialize("bindmonitor_tailcall", EBPF_EXECUTION_NATIVE);
    _helper.initialize(
        _native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        "BindMonitor",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);
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

void
bind_tailcall_test(_In_ struct bpf_object* object)
{
    UNREFERENCED_PARAMETER(object);
    WSAData data;
    SOCKET sockets[2];
    REQUIRE(WSAStartup(2, &data) == 0);

    // Now, trigger bind. bind should not succeed.
    REQUIRE(perform_bind(&sockets[0], 30000) != 0);
    REQUIRE(perform_bind(&sockets[1], 30001) != 0);

    WSACleanup();
}

#define SOCKET_TEST_PORT 0x3bbf

void
send_traffic(IPPROTO protocol, bool is_ipv6)
{
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    PSOCKADDR local_address = nullptr;
    int local_address_length = 0;

    if (protocol == IPPROTO_UDP) {
        datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
        datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);
        // Send some traffic to initiate a connect.
        datagram_client_socket.get_local_address(local_address, local_address_length);
        // Post an asynchronous receive on the receiver socket.
        datagram_server_socket.post_async_receive();

        // Send loopback message to test port.
        if (is_ipv6) {
            IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
        } else {
            IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
        }

        datagram_client_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);

        datagram_server_socket.complete_async_receive(false);
        // Cancel send operation.
        datagram_client_socket.cancel_send_message();
    } else // TCP traffic.
    {
        stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
        stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);
        stream_client_socket.get_local_address(local_address, local_address_length);
        // Post an asynchronous receive on the receiver socket.
        stream_server_socket.post_async_receive();

        // Send loopback message to test port.
        if (is_ipv6) {
            IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
        } else {
            IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
        }

        stream_client_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);

        stream_server_socket.complete_async_receive(false);
        // Cancel send operation.
        stream_client_socket.cancel_send_message();
    }
}

void
run_process_start_key_test(IPPROTO protocol, bool is_ipv6)
{
    // Load and attach ebpf program.
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

        // Initialize WSA so we can send traffic.
        wsa_helper.initialize();

        send_traffic(protocol, is_ipv6);

        // Read from map.
        std::cout << "bpf_object__find_map_by_name(process_start_key_map)\n";
        map = bpf_object__find_map_by_name(object, "process_start_key_map");
        REQUIRE(map != nullptr);
        REQUIRE(map->map_fd != ebpf_fd_invalid);

        uint32_t key = 0;
        typedef struct _value
        {
            uint32_t current_pid;
            uint64_t start_key;
        } value_t;
        value_t found_value{};
        std::cout << "bpf_map_lookup_elem(process_start_key_map) key: " << key << "\n";
        REQUIRE(bpf_map_lookup_elem(bpf_map__fd(map), &key, &found_value) == 0);

        std::cout << "bpf_map_delete_elem(process_start_key_map)\n";
        REQUIRE(bpf_map_delete_elem(bpf_map__fd(map), &key) == 0);

        // Verify PID/Start Key values.
        // We only validate that the start_key is not zero because
        // otherwise this test case would need to take a dependency on NtQueryInformationProcess
        // which per documentation can change at any time.
        unsigned long pid = GetCurrentProcessId();
        REQUIRE(0 < found_value.start_key);
        REQUIRE(pid == found_value.current_pid);
    }
}

void
run_thread_start_time_test(IPPROTO protocol, bool is_ipv6)
{
    // Load and attach ebpf program.
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

        // Initialize WSA so we can send traffic.
        wsa_helper.initialize();

        send_traffic(protocol, is_ipv6);

        // Read from map.
        std::cout << "bpf_object__find_map_by_name(thread_start_time_map)\n";
        map = bpf_object__find_map_by_name(object, "thread_start_time_map");
        REQUIRE(map != nullptr);
        REQUIRE(map->map_fd != ebpf_fd_invalid);

        uint32_t key = 0;
        typedef struct _value
        {
            uint32_t current_tid;
            int64_t start_time;
        } value_t;
        value_t found_value{};
        std::cout << "bpf_map_lookup_elem(thread_start_time_map) key: " << key << "\n";
        REQUIRE(bpf_map_lookup_elem(bpf_map__fd(map), &key, &found_value) == 0);

        std::cout << "bpf_map_delete_elem(thread_start_time_map)\n";
        REQUIRE(bpf_map_delete_elem(bpf_map__fd(map), &key) == 0);
        // Verify PID/start time values.
        unsigned long tid = GetCurrentThreadId();
        long long start_time = 0;
        FILETIME creation, exit, kernel, user;
        if (GetThreadTimes(GetCurrentThread(), &creation, &exit, &kernel, &user)) {
            start_time = static_cast<long long>(creation.dwLowDateTime) |
                         (static_cast<long long>(creation.dwHighDateTime) << 32);
        }
        REQUIRE(tid == found_value.current_tid);
        REQUIRE(start_time == found_value.start_time);
    }
}

#define MAX_TAIL_CALL_PROGS MAX_TAIL_CALL_CNT + 2

TEST_CASE("bind_tailcall_max_native_test", "[native_tests]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);

    program_load_attach_helper_t _helper;
    native_module_helper_t _native_helper;
    _native_helper.initialize("tail_call_max_exceed", EBPF_EXECUTION_NATIVE);
    _helper.initialize(
        _native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        "bind_test_caller",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);
    object = _helper.get_object();

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(object, "bind_tail_call_map");
    REQUIRE(prog_map_fd > 0);

    struct bpf_program* caller = bpf_object__find_program_by_name(object, "bind_test_caller");
    REQUIRE(caller != nullptr);

    // Check each tail call program in the map.
    for (int i = 0; i < MAX_TAIL_CALL_PROGS; i++) {
        std::string program_name{"bind_test_callee"};
        program_name += std::to_string(i);

        struct bpf_program* program = bpf_object__find_program_by_name(object, program_name.c_str());
        REQUIRE(program != nullptr);
    }

    // Perform bind test.
    bind_tailcall_test(object);

    // Clean up tail calls.
    for (int index = 0; index < MAX_TAIL_CALL_PROGS; index++) {
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    }
}

TEST_CASE("bpf_get_current_pid_tgid", "[helpers]")
{
    // Load and attach ebpf program.
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    uint32_t ifindex = 0;
    const char* program_name = "func";
    program_load_attach_helper_t _helper;
    native_module_helper_t _native_helper;
    _native_helper.initialize("pidtgid", EBPF_EXECUTION_NATIVE);
    _helper.initialize(
        _native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        program_name,
        EBPF_EXECUTION_NATIVE,
        &ifindex,
        sizeof(ifindex),
        hook);
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

TEST_CASE("bpf_get_process_start_key_udp_ipv4", "[helpers]") { run_process_start_key_test(IPPROTO_UDP, false); }

TEST_CASE("bpf_get_process_start_key_udp_ipv6", "[helpers]") { run_process_start_key_test(IPPROTO_UDP, true); }

TEST_CASE("bpf_get_process_start_key_tcp_ipv4", "[helpers]") { run_process_start_key_test(IPPROTO_TCP, false); }

TEST_CASE("bpf_get_process_start_key_tcp_ipv6", "[helpers]") { run_process_start_key_test(IPPROTO_TCP, true); }

TEST_CASE("bpf_get_thread_start_time_udp_ipv4", "[helpers]") { run_thread_start_time_test(IPPROTO_UDP, false); }

TEST_CASE("bpf_get_thread_start_time_udp_ipv6", "[helpers]") { run_thread_start_time_test(IPPROTO_UDP, true); }
TEST_CASE("bpf_get_thread_start_time_tcp_ipv4", "[helpers]") { run_thread_start_time_test(IPPROTO_TCP, false); }

TEST_CASE("bpf_get_thread_start_time_tcp_ipv6", "[helpers]") { run_thread_start_time_test(IPPROTO_TCP, true); }

TEST_CASE("native_module_handle_test", "[native_tests]")
{
    int result;
    native_module_helper_t _native_helper;
    _native_helper.initialize("bindmonitor", EBPF_EXECUTION_NATIVE);
    struct bpf_object* object = nullptr;
    struct bpf_object* object2 = nullptr;
    fd_t program_fd;

    result = program_load_helper(
        _native_helper.get_file_name().c_str(), BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object, &program_fd);
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
    result = program_load_helper(
        _native_helper.get_file_name().c_str(), BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object2, &program_fd);
    REQUIRE(result == -ENOENT);

    // Close the native module handle. That should result in the module to be unloaded.
    REQUIRE(_close(native_module_fd) == 0);
    object->native_module_fd = ebpf_fd_invalid;

    // Add a sleep to allow the previous driver to be unloaded successfully.
    Sleep(1000);

    // Try to load the same native module again. It should succeed this time.
    object2 = nullptr;
    result = program_load_helper(
        _native_helper.get_file_name().c_str(), BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object2, &program_fd);
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
    native_module_helper_t _native_helper;
    _native_helper.initialize("printk", EBPF_EXECUTION_NATIVE);
    _helper.initialize(
        _native_helper.get_file_name().c_str(), BPF_PROG_TYPE_BIND, "func", EBPF_EXECUTION_NATIVE, nullptr, 0, hook);
    auto object = _helper.get_object();
    REQUIRE(object != nullptr);
}

TEST_CASE("bpf_user_helpers_test_native", "[api_test]") { bpf_user_helpers_test(EBPF_EXECUTION_NATIVE); }

// This test tests resource reclamation and clean-up after a premature/abnormal user mode application exit.
TEST_CASE("close_unload_test", "[native_tests][native_close_cleanup_tests]")
{
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper;
    native_module_helper_t _native_helper;
    _native_helper.initialize("bindmonitor_tailcall", EBPF_EXECUTION_NATIVE);
    _helper.initialize(
        _native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        "BindMonitor",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);
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

TEST_CASE("ioctl_stress", "[stress]")
{
    // Load bindmonitor_ringbuf.sys

    struct bpf_object* object = nullptr;
    fd_t program_fd;

    native_module_helper_t _native_helper;
    _native_helper.initialize("bindmonitor_ringbuf", EBPF_EXECUTION_NATIVE);
    REQUIRE(
        program_load_helper(
            _native_helper.get_file_name().c_str(), BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object, &program_fd) ==
        0);

    // Create a test array map to provide target for the ioctl stress test.
    fd_t test_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "test_map", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);

    // Get fd of process_map map.
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");

    // Subscribe to the ring buffer with empty callback (using async mode for automatic callbacks).
    ebpf_ring_buffer_opts ring_opts{.sz = sizeof(ring_opts), .flags = EBPF_RINGBUF_FLAG_AUTO_CALLBACK};
    auto ring = ebpf_ring_buffer__new(process_map_fd, [](void*, void*, size_t) { return 0; }, nullptr, &ring_opts);

    // Run 4 threads per cpu.
    // Get cpu count.
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    std::atomic<size_t> failure_count = 0;
    std::vector<std::jthread> threads;
    std::atomic<bool> stop_requested;
    for (DWORD i = 0; i < sysinfo.dwNumberOfProcessors; i++) {
        for (int j = 0; j < 4; j++) {
            threads.emplace_back([&]() {
                while (!stop_requested) {
                    int test_case = rand() % 4;
                    uint32_t key = 0;
                    uint32_t value;
                    bpf_test_run_opts opts = {};
                    struct
                    {
                        EBPF_CONTEXT_HEADER;
                        bind_md_t context;
                    } ctx_header = {0};
                    bind_md_t* ctx = &ctx_header.context;
                    int result;
                    switch (test_case) {
                    case 0:
                        // Test bpf_map_lookup_elem
                        result = bpf_map_lookup_elem(test_map_fd, &key, &value);
                        if (result != 0) {
                            std::cout << "bpf_map_lookup_elem failed with " << result << std::endl;
                            failure_count++;
                        }
                        break;
                    case 1:
                        // Test bpf_map_update_elem
                        result = bpf_map_update_elem(test_map_fd, &key, &value, 0);
                        if (result != 0) {
                            std::cout << "bpf_map_update_elem failed with " << result << std::endl;
                            failure_count++;
                        }
                        break;
                    case 2:
                        // Test bpf_map_delete_elem
                        result = bpf_map_delete_elem(test_map_fd, &key);
                        if (result != 0) {
                            std::cout << "bpf_map_delete_elem failed with " << result << std::endl;
                            failure_count++;
                        }
                        break;
                    case 3:
                        // Run the program to trigger a ring buffer event
                        std::string app_id = "api_test.exe";

                        opts.ctx_in = ctx;
                        opts.ctx_size_in = sizeof(*ctx);
                        opts.ctx_out = ctx;
                        opts.ctx_size_out = sizeof(*ctx);
                        opts.data_in = app_id.data();
                        opts.data_size_in = static_cast<uint32_t>(app_id.size());
                        opts.data_out = app_id.data();
                        opts.data_size_out = static_cast<uint32_t>(app_id.size());

                        result = bpf_prog_test_run_opts(program_fd, &opts);
                        if (result != 0) {
                            std::cout << "bpf_prog_test_run_opts failed with " << result << std::endl;
                            failure_count++;
                        }
                        break;
                    }
                };
            });
        }
    }

    // Wait for 60 seconds
    std::this_thread::sleep_for(std::chrono::seconds(60));

    stop_requested = true;

    for (auto& t : threads) {
        t.join();
    }
    REQUIRE(failure_count == 0);

    // Unsubscribe from the ring buffer
    ring_buffer__free(ring);

    // Clean up
    bpf_object__close(object);
    _close(test_map_fd);
}

typedef struct _ring_buffer_test_context
{
    uint32_t event_count = 0;
    uint32_t expected_event_count = 0;
    std::promise<void> promise;
} ring_buffer_test_context_t;

void
trigger_ring_buffer_events(fd_t program_fd, uint32_t expected_event_count, _Inout_ void* data, uint32_t data_size)
{
    // Get cpu count
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    // Create 2 threads per CPU that invoke the program to trigger ring buffer events.
    const uint32_t thread_count = 2;
    uint32_t total_threads = thread_count * sysinfo.dwNumberOfProcessors;
    // Round up the iterations per thread to ensure at least expected_event_count events are raised.
    uint32_t iterations_per_thread = (expected_event_count + total_threads + 1) / total_threads;

    std::vector<std::jthread> threads;
    std::atomic<size_t> failure_count = 0;
    for (DWORD i = 0; i < sysinfo.dwNumberOfProcessors; i++) {
        for (uint32_t j = 0; j < thread_count; j++) {
            threads.emplace_back([&, i]() {
                bind_md_t ctx = {};
                bpf_test_run_opts opts = {};
                opts.ctx_in = &ctx;
                opts.ctx_size_in = sizeof(ctx);
                opts.ctx_out = &ctx;
                opts.ctx_size_out = sizeof(ctx);
                opts.cpu = static_cast<uint32_t>(i);
                opts.data_in = data;
                opts.data_size_in = data_size;
                opts.data_out = data;
                opts.data_size_out = data_size;

                for (uint32_t k = 0; k < iterations_per_thread; k++) {
                    int result = bpf_prog_test_run_opts(program_fd, &opts);
                    if (result != 0) {
                        std::cout << "bpf_prog_test_run_opts failed with " << result << std::endl;
                        failure_count++;
                        break;
                    }
                }
            });
        }
    }

    // Wait for threads to complete.
    for (auto& t : threads) {
        t.join();
    }

    REQUIRE(failure_count == 0);
}

TEST_CASE("test_ringbuffer_concurrent_wraparound", "[stress][ring_buffer]")
{
    // Load bindmonitor_ringbuf.sys.
    struct bpf_object* object = nullptr;
    fd_t program_fd = ebpf_fd_invalid;
    ring_buffer_test_context_t context;
    std::string app_id = "api_test.exe";
    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor_ringbuf", EBPF_EXECUTION_NATIVE);

    REQUIRE(
        program_load_helper(
            native_helper.get_file_name().c_str(), BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object, &program_fd) ==
        0);

    // Get fd of process_map map.
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");

    uint32_t max_entries = bpf_map__max_entries(bpf_object__find_map_by_name(object, "process_map"));
    uint32_t max_iterations = static_cast<uint32_t>(10 * (max_entries / app_id.size()));

    // Initialize context.
    context.event_count = 0;
    context.expected_event_count = max_iterations;
    auto ring_buffer_event_callback = context.promise.get_future();
    // Subscribe to the ring buffer (using async mode for automatic callbacks).
    ebpf_ring_buffer_opts ring_opts{.sz = sizeof(ring_opts), .flags = EBPF_RINGBUF_FLAG_AUTO_CALLBACK};
    auto ring = ebpf_ring_buffer__new(
        process_map_fd,
        [](void* ctx, void*, size_t) {
            ring_buffer_test_context_t* context = reinterpret_cast<ring_buffer_test_context_t*>(ctx);
            if (++context->event_count == context->expected_event_count) {
                context->promise.set_value();
            }
            return 0;
        },
        &context,
        &ring_opts);

    // trigger ring buffer events from multiple threads across all CPUs.
    trigger_ring_buffer_events(
        program_fd, context.expected_event_count, app_id.data(), static_cast<uint32_t>(app_id.size()));

    // Wait for 1 second for the ring buffer to receive all events.
    REQUIRE(ring_buffer_event_callback.wait_for(1s) == std::future_status::ready);

    // Unsubscribe from the ring buffer.
    ring_buffer__free(ring);

    // Clean up.
    bpf_object__close(object);
}

TEST_CASE("test_ringbuffer_wraparound", "[ring_buffer]")
{
    const auto capacity = 4096;
    std::string app_id = "api_test.exe";
    const auto record_size = 0x18; // record header + data aligned to 8 bytes.
    const auto iterations = static_cast<uint32_t>(capacity / record_size) * 2;

    fd_t map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "test_ringbuf", 0, 0, capacity, nullptr);
    REQUIRE(map_fd > 0);

    const volatile LONG64* producer_ptr = nullptr;
    volatile LONG64* consumer_ptr = nullptr;
    const uint8_t* data = nullptr;
    size_t data_size = 0;

    ebpf_result_t result =
        ebpf_ring_buffer_map_map_buffer(map_fd, (void**)&consumer_ptr, (const void**)&producer_ptr, &data, &data_size);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(producer_ptr != nullptr);
    REQUIRE(consumer_ptr != nullptr);
    REQUIRE(data != nullptr);

    for (uint32_t i = 0; i < iterations; i++) {
        REQUIRE(ebpf_ring_buffer_map_write(map_fd, app_id.data(), app_id.size()) == EBPF_SUCCESS);

        uint64_t prod = ReadAcquire64(producer_ptr);
        uint64_t cons = ReadAcquire64(consumer_ptr);
        REQUIRE(prod >= cons);
        REQUIRE(prod - cons < 4096);

        // Consume all data.
        WriteRelease64(consumer_ptr, prod);
    }

    // Clean up.
    _close(map_fd);
}

typedef struct _perf_event_array_test_context
{
    std::atomic<size_t> event_count = 0;
    uint32_t expected_event_count = 0;
    uint32_t cpu_count = 0;
    uint64_t event_length = 0;
    std::atomic<size_t> lost_count = 0;
    std::promise<void> promise;
} perf_event_array_test_context_t;

TEST_CASE("test_perfbuffer", "[stress][perf_buffer]")
{
    // Load bindmonitor_perf_event_array.sys.
    struct bpf_object* object = nullptr;
    fd_t program_fd = ebpf_fd_invalid;
    perf_event_array_test_context_t context;
    std::string app_id = "api_test.exe";
    uint32_t cpu_count = libbpf_num_possible_cpus();
    CAPTURE(cpu_count);
    context.cpu_count = cpu_count;
    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor_perf_event_array", EBPF_EXECUTION_NATIVE);

    REQUIRE(
        program_load_helper(
            native_helper.get_file_name().c_str(), BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object, &program_fd) ==
        0);

    // Get fd of process_map map.
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");

    uint32_t max_entries = bpf_map__max_entries(bpf_object__find_map_by_name(object, "process_map"));
    uint32_t max_iterations = static_cast<uint32_t>(10 * (max_entries / app_id.size()));
    CAPTURE(max_entries, max_iterations);

    // Initialize context.
    context.event_count = 0;
    context.expected_event_count = max_iterations;
    auto perf_buffer_event_callback = context.promise.get_future();
    // Subscribe to the perf buffer.
    ebpf_perf_buffer_opts perf_opts{.sz = sizeof(perf_opts), .flags = EBPF_PERFBUF_FLAG_AUTO_CALLBACK};
    auto perfbuffer = ebpf_perf_buffer__new(
        process_map_fd,
        0,
        [](void* ctx, int, void* data, uint32_t length) {
            perf_event_array_test_context_t* context = reinterpret_cast<perf_event_array_test_context_t*>(ctx);

            if ((data == nullptr) || (length == 0)) {
                return;
            }
            if (((++context->event_count) + (context->lost_count)) >= context->expected_event_count) {
                try {
                    context->promise.set_value();
                } catch (const std::future_error& e) {
                    // Ignore the exception if the promise was already set.
                    if (e.code() != std::future_errc::promise_already_satisfied) {
                        throw; // Rethrow if it's a different error.
                    }
                }
            }
            return;
        },
        [](void* ctx, int, uint64_t count) {
            perf_event_array_test_context_t* context = reinterpret_cast<perf_event_array_test_context_t*>(ctx);
            context->lost_count += count;
            return;
        },
        &context,
        &perf_opts);

    // Trigger perf buffer events from multiple threads across all CPUs.
    trigger_ring_buffer_events(
        program_fd, context.expected_event_count, app_id.data(), static_cast<uint32_t>(app_id.size()));

    // Wait for 1 second for the ring buffer to receive all events.
    bool test_complete = perf_buffer_event_callback.wait_for(1s) == std::future_status::ready;

    CAPTURE(context.event_length, context.event_count, context.expected_event_count, context.lost_count);

    REQUIRE(test_complete == true);

    // Unsubscribe from the ring buffer.
    perf_buffer__free(perfbuffer);

    // Clean up.
    bpf_object__close(object);
}

TEST_CASE("Test program order", "[native_tests]")
{
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    uint32_t program_count = 4;
    int result;

    native_module_helper_t _native_helper;
    _native_helper.initialize("multiple_programs", EBPF_EXECUTION_NATIVE);
    REQUIRE(
        program_load_helper(
            _native_helper.get_file_name().c_str(),
            BPF_PROG_TYPE_SAMPLE,
            EBPF_EXECUTION_NATIVE,
            &object,
            &program_fd) == 0);

    // Get all 4 programs in the native object, and invoke them using bpf_prog_test_run.
    //
    // If there is a mismatch in the sorting order of bpf2c and ebpfapi, the 4 eBPF programs
    // in this object file will be initialized with wrong handles. That will cause wrong programs
    // to be invoked when bpf_prog_test_run is called. Since each program returns a different value,
    // we can validate that the correct / expected program was invoked by checking the return value.
    for (uint32_t i = 0; i < program_count; i++) {
        bpf_test_run_opts opts = {};
        bind_md_t ctx = {};
        std::string program_name = "program" + std::to_string(i + 1);
        struct bpf_program* program = bpf_object__find_program_by_name(object, program_name.c_str());
        REQUIRE(program != nullptr);
        program_fd = bpf_program__fd(program);
        REQUIRE(program_fd > 0);

        std::string app_id = "api_test.exe";

        opts.ctx_in = &ctx;
        opts.ctx_size_in = sizeof(ctx);
        opts.ctx_out = &ctx;
        opts.ctx_size_out = sizeof(ctx);
        opts.data_in = app_id.data();
        opts.data_size_in = static_cast<uint32_t>(app_id.size());
        opts.data_out = app_id.data();
        opts.data_size_out = static_cast<uint32_t>(app_id.size());

        result = bpf_prog_test_run_opts(program_fd, &opts);
        REQUIRE(result == 0);
        REQUIRE(opts.retval == (i + 1));
    }

    // Clean up.
    bpf_object__close(object);
}

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
    const int num_inner_maps = 5;
    fd_t inner_map_fds[num_inner_maps];
    uint32_t inner_map_ids[num_inner_maps];
    fd_t outer_map_fd = 0;
    uint32_t outer_map_id = 0;

    for (int i = 0; i < num_inner_maps; ++i) {
        std::string name = "inner_map" + std::to_string(i + 1);
        inner_map_fds[i] =
            bpf_map_create(BPF_MAP_TYPE_ARRAY, name.c_str(), sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
        REQUIRE(inner_map_fds[i] > 0);
    }

    // Create outer map with the inner map handle in options.
    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fds[0]};
    outer_map_fd = bpf_map_create(map_type, "outer_map", sizeof(uint32_t), sizeof(fd_t), 2 * num_inner_maps, &opts);
    REQUIRE(outer_map_fd > 0);

    // Close outer map FD so that it is deleted. Validates that empty outer map is deleted.
    _close(outer_map_fd);

    // Create outer map again with the inner map handle in options.
    opts = {.inner_map_fd = (uint32_t)inner_map_fds[0]};
    outer_map_fd = bpf_map_create(map_type, "outer_map", sizeof(uint32_t), sizeof(fd_t), 2 * num_inner_maps, &opts);
    REQUIRE(outer_map_fd > 0);

    // Query outer map ID.
    bpf_map_info info;
    uint32_t info_size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(outer_map_fd, &info, &info_size) == 0);
    REQUIRE(info.id > 0);
    REQUIRE(info.type == map_type);

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
        _close(inner_map_fds[i]);
    }

    // For each inner map, get the inner map ID from outer map and query the value from it.
    for (int i = 0; i < num_inner_maps; ++i) {
        uint32_t key = i;
        uint32_t result = bpf_map_lookup_elem(outer_map_fd, &key, &inner_map_ids[i]);
        REQUIRE(result == 0);
        REQUIRE(inner_map_ids[i] > 0);
        fd_t inner_map_fd = bpf_map_get_fd_by_id(inner_map_ids[i]);
        REQUIRE(inner_map_fd > 0);
        // Query value from inner_map
        key = 0;
        uint32_t value = 0;
        result = bpf_map_lookup_elem(inner_map_fd, &key, &value);
        REQUIRE(result == ERROR_SUCCESS);
        REQUIRE(value == static_cast<uint32_t>(100 + i));
        _close(inner_map_fd);
    }

    _close(outer_map_fd);

    // Now all the maps should be closed.
    REQUIRE(bpf_map_get_next_id(0, &outer_map_id) < 0);
    for (int i = 0; i < num_inner_maps; ++i) {
        REQUIRE(bpf_map_get_next_id(0, &inner_map_ids[i]) < 0);
    }
}

TEST_CASE("array_map_of_maps_user_reference", "[user_reference]")
{
    _test_nested_maps_user_reference(BPF_MAP_TYPE_ARRAY_OF_MAPS);
}
TEST_CASE("hash_map_of_maps_user_reference", "[user_reference]")
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
    int result;
    struct bpf_object* object = nullptr;
    const int program_count = 3;
    fd_t program_fd;
    fd_t program_fds[program_count] = {0};
    uint32_t program_ids[program_count] = {0};

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_tailcall.sys" : "bindmonitor_tailcall.o");

    result = program_load_helper(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &object, &program_fd);
    REQUIRE(result == 0);

    const char* program_names[program_count] = {"BindMonitor", "BindMonitor_Callee0", "BindMonitor_Callee1"};

    // Create a new prog_array_map with 3 entries.
    fd_t prog_array_map_fd =
        bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, "prog_array_map", sizeof(uint32_t), sizeof(fd_t), 3, nullptr);
    REQUIRE(prog_array_map_fd > 0);

    // Get FDs for the three programs in a loop.
    for (uint32_t i = 0; i < program_count; i++) {
        struct bpf_program* program = bpf_object__find_program_by_name(object, program_names[i]);
        REQUIRE(program != nullptr);
        program_fds[i] = bpf_program__fd(program);
        REQUIRE(program_fds[i] > 0);
    }

    // Insert the program FDs into the prog_array_map in a loop.
    for (uint32_t i = 0; i < program_count; i++) {
        uint32_t index = i;
        REQUIRE(bpf_map_update_elem(prog_array_map_fd, &index, &program_fds[i], 0) == 0);
    }
    // Close the program FDs. The programs should still exist and can be queried from the prog_array_map.
    bpf_object__close(object);

    // Create an array of program FDs and get the program FDs from the prog_array_map in a loop.
    for (uint32_t i = 0; i < program_count; i++) {
        REQUIRE(bpf_map_lookup_elem(prog_array_map_fd, &i, &program_ids[i]) == 0);
        REQUIRE(program_ids[i] > 0);
        program_fds[i] = bpf_prog_get_fd_by_id(program_ids[i]);
        REQUIRE(program_fds[i] > 0);
    }

    // Query object info for each program.
    for (uint32_t i = 0; i < program_count; i++) {
        bpf_prog_info program_info = {};
        uint32_t program_info_size = sizeof(program_info);
        REQUIRE(bpf_obj_get_info_by_fd(program_fds[i], &program_info, &program_info_size) == 0);
    }

    // Query map ID.
    bpf_map_info info;
    uint32_t info_size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(prog_array_map_fd, &info, &info_size) == 0);
    REQUIRE(info.id > 0);
    REQUIRE(info.type == BPF_MAP_TYPE_PROG_ARRAY);

    // Close the program FDs, followed by the prog_array_map FD.
    for (uint32_t i = 0; i < program_count; i++) {
        _close(program_fds[i]);
    }
    _close(prog_array_map_fd);

    // The programs and maps should be closed now. Query FDs for each program and map and ensure they are invalid.
    for (uint32_t i = 0; i < program_count; i++) {
        REQUIRE(bpf_prog_get_fd_by_id(program_ids[i]) < 0);
    }
    REQUIRE(bpf_map_get_fd_by_id(info.id) < 0);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("prog_array_map_user_reference-jit", "[user_reference]")
{
    _test_prog_array_map_user_reference(EBPF_EXECUTION_JIT);
}
#endif
TEST_CASE("prog_array_map_user_reference-native", "[user_reference]")
{
    _test_prog_array_map_user_reference(EBPF_EXECUTION_NATIVE);
}

TEST_CASE("native_load_retry_after_insufficient_buffers", "[native_tests]")
{
    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor", EBPF_EXECUTION_NATIVE);

    std::vector<fd_t> map_fds(3, ebpf_fd_invalid);
    std::vector<fd_t> program_fds(1, ebpf_fd_invalid);
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;

    ebpf_result_t result = ebpf_object_load_native_by_fds(
        native_helper.get_file_name().c_str(), &count_of_maps, nullptr, &count_of_programs, nullptr);

    REQUIRE(result == EBPF_NO_MEMORY);
    REQUIRE(count_of_maps == map_fds.size());
    REQUIRE(count_of_programs == program_fds.size());

    result = ebpf_object_load_native_by_fds(
        native_helper.get_file_name().c_str(), &count_of_maps, map_fds.data(), &count_of_programs, program_fds.data());

    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(count_of_maps == map_fds.size());
    REQUIRE(count_of_programs == program_fds.size());

    for (auto fd : map_fds) {
        REQUIRE(fd != ebpf_fd_invalid);
        _close(fd);
    }
    for (auto fd : program_fds) {
        REQUIRE(fd != ebpf_fd_invalid);
        _close(fd);
    }
}

TEST_CASE("load_all_sample_programs", "[native_tests][!mayfail]")
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
        {"multiple_programs.sys", BPF_PROG_TYPE_UNSPEC},
        {"pidtgid.sys", BPF_PROG_TYPE_UNSPEC},
        {"printk.sys", BPF_PROG_TYPE_UNSPEC},
        {"printk_legacy.sys", BPF_PROG_TYPE_UNSPEC},
        {"process_start_key.sys", BPF_PROG_TYPE_UNSPEC},
        {"sockops.sys", BPF_PROG_TYPE_UNSPEC},
        {"strings.sys", BPF_PROG_TYPE_UNSPEC},
        {"tail_call_max_exceed.sys", BPF_PROG_TYPE_UNSPEC},
        {"thread_start_time.sys", BPF_PROG_TYPE_UNSPEC},
        {"utility.sys", BPF_PROG_TYPE_UNSPEC}};

    _test_multiple_programs_load(_countof(test_parameters), test_parameters, EBPF_EXECUTION_NATIVE, 0);
}

TEST_CASE("extensible_maps_user_apis", "[extensible_maps]")
{
    // This test validates extensible map user APIs.
    fd_t extensible_map_fd = bpf_map_create(
        BPF_MAP_TYPE_SAMPLE_ARRAY_MAP, "extensible_map", sizeof(uint32_t), sizeof(uint32_t), 100, nullptr);
    REQUIRE(extensible_map_fd > 0);

    // Update elements at various indices.
    for (uint32_t i = 0; i < 10; i++) {
        uint32_t key = i * 10;
        uint32_t value = i + 100;
        int result = bpf_map_update_elem(extensible_map_fd, &key, &value, 0);
        REQUIRE(result == ERROR_SUCCESS);
    }

    // Lookup elements and validate values.
    for (uint32_t i = 0; i < 10; i++) {
        uint32_t key = i * 10;
        uint32_t value = 0;
        int result = bpf_map_lookup_elem(extensible_map_fd, &key, &value);
        REQUIRE(result == ERROR_SUCCESS);
        REQUIRE(value == i + 100);
    }

    // Delete some elements.
    for (uint32_t i = 0; i < 5; i++) {
        uint32_t key = i * 10;
        int result = bpf_map_delete_elem(extensible_map_fd, &key);
        REQUIRE(result == ERROR_SUCCESS);
    }

    // Validate deleted elements are no longer present.
    for (uint32_t i = 0; i < 5; i++) {
        uint32_t key = i * 10;
        uint32_t value = 0;
        int result = bpf_map_lookup_elem(extensible_map_fd, &key, &value);
        // Since this is an array map, lookup should succeed but value should be zero.
        REQUIRE(result == ERROR_SUCCESS);
        REQUIRE(value == 0);
    }

    // Clean up
    _close(extensible_map_fd);
}

void
_test_extensible_maps_program_load_common(ebpf_map_type_t type, ebpf_execution_type_t execution_type)
{
    bpf_object_ptr unique_object{nullptr};
    int result;
    fd_t program_fd;
    bpf_link_ptr link;
    int iteration = 10;
    bpf_object* object = nullptr;

    native_module_helper_t test_sample_ebpf_helper;
    test_sample_ebpf_helper.initialize("extensible_map_basic", execution_type);

    result = program_load_helper(
        test_sample_ebpf_helper.get_file_name().c_str(), BPF_PROG_TYPE_SAMPLE, execution_type, &object, &program_fd);
    REQUIRE(result == 0);

    unique_object.reset(object);

    const char* map_name = (type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) ? "sample_array_map" : "sample_hash_map";
    fd_t result_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "result_map");
    REQUIRE(result_map_fd > 0);

    fd_t sample_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), map_name);
    REQUIRE(sample_map_fd > 0);

    auto validate_result_map = [&](uint32_t expected_value) {
        uint32_t key = 0;
        uint32_t result_value = 0;
        REQUIRE(bpf_map_lookup_elem(result_map_fd, &key, &result_value) == 0);
        REQUIRE(result_value == expected_value);
    };

    auto validate_sample_map_value = [&](uint32_t expected_value, bool expect_lookup_to_fail = false) {
        uint32_t key = 0;
        uint32_t map_value = 0;
        if (expect_lookup_to_fail) {
            REQUIRE(bpf_map_lookup_elem(sample_map_fd, &key, &map_value) != 0);
            return;
        } else {
            REQUIRE(bpf_map_lookup_elem(sample_map_fd, &key, &map_value) == 0);
            REQUIRE(map_value == expected_value);
        }
    };

    // Set config map.
    fd_t config_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "config_map");
    REQUIRE(config_map_fd > 0);
    uint32_t config_key = 0;
    uint32_t config_value = type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP ? 1 : 2;
    REQUIRE((bpf_map_update_elem(config_map_fd, &config_key, &config_value, 0) == 0));

    // Set initial value in the map.
    uint32_t key = 0;
    uint32_t value = 1234;
    REQUIRE((bpf_map_update_elem(sample_map_fd, &key, &value, 0) == 0));

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
    REQUIRE(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

    // Lookup the sample map value and validate it is updated.
    validate_sample_map_value(value + iteration);
    validate_result_map(1);
    value += iteration;

    // Now invoke "test_map_read_helper_increment" program. The map value should be incremented by 1 by the program for
    // each iteration.
    program_fd =
        bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_read_helper_increment"));
    REQUIRE(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

    // Lookup the sample map value and validate it is updated.
    validate_sample_map_value(value + iteration);
    validate_result_map(1);
    value += iteration;

    // Set iteration to 1 for the remaining tests.
    opts.repeat = 1;

    // Now invoke "test_map_read_helper_increment_invalid" program. Map lookup should fail in this case.
    program_fd = bpf_program__fd(
        bpf_object__find_program_by_name(unique_object.get(), "test_map_read_helper_increment_invalid"));
    REQUIRE(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

    // Validate that the program failed by checking the result map.
    validate_result_map(0);

    // Now invoke "test_map_update_element" program. The value should be set to 42.
    program_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_update_element"));
    REQUIRE(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

    // Lookup the sample map value and validate it is set to 42.
    validate_sample_map_value(42);
    validate_result_map(1);

    // Now invoke "test_map_delete_element" program. The value should be deleted and set to 0.
    program_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_delete_element"));
    REQUIRE(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

    // Lookup the sample map value and validate it is set to 0.
    if (type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
        validate_sample_map_value(0);
    } else {
        validate_sample_map_value(0, true);
    }
    validate_result_map(1);

    // Set map value to 200.
    value = 200;
    REQUIRE((bpf_map_update_elem(sample_map_fd, &key, &value, 0) == 0));

    // Invoke "test_map_find_and_delete_element" program.
    program_fd =
        bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_find_and_delete_element"));
    REQUIRE(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

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
    REQUIRE(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

    // push_elem is not supported for array or hash maps, validate that the call failed.
    validate_result_map(0);

    // Invoke "test_map_pop_elem" program.
    program_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_pop_elem"));
    REQUIRE(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

    // pop_elem is not supported for array or hash maps, validate that the call failed.
    validate_result_map(0);

    // Invoke "test_map_peek_elem" program.
    program_fd = bpf_program__fd(bpf_object__find_program_by_name(unique_object.get(), "test_map_peek_elem"));
    REQUIRE(program_fd > 0);
    result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

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

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("extensible_maps_program_load-jit", "[extensible_maps]")
{
    _test_extensible_maps_program_load(EBPF_EXECUTION_JIT);
}
#endif
TEST_CASE("extensible_maps_program_load-native", "[extensible_maps]")
{
    _test_extensible_maps_program_load(EBPF_EXECUTION_NATIVE);
}
