// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "api_internal.h"
#include "api_test.h"
#include "api_test_jit.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_core_structs.h"
#include "ebpf_ring_buffer_record.h"
#include "ebpf_store_helper.h"
#include "ebpf_structs.h"
#include "misc_helper.h"
#include "native_helper.hpp"
#include "program_helper.h"
#include "sample_ext_helpers.h"
#include "service_helper.h"
#include "socket_helper.h"
#include "watchdog.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <chrono>
#include <functional>
#include <io.h>
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

using jit_t = std::integral_constant<ebpf_execution_type_t, EBPF_EXECUTION_JIT>;
using native_t = std::integral_constant<ebpf_execution_type_t, EBPF_EXECUTION_NATIVE>;
using interpret_t = std::integral_constant<ebpf_execution_type_t, EBPF_EXECUTION_INTERPRET>;

#if defined(CONFIG_BPF_JIT_DISABLED) && defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define ENABLED_EXECUTION_TYPES native_t
#elif defined(CONFIG_BPF_JIT_DISABLED)
#define ENABLED_EXECUTION_TYPES native_t, interpret_t
#elif defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define ENABLED_EXECUTION_TYPES native_t, jit_t
#else
#define ENABLED_EXECUTION_TYPES native_t, jit_t, interpret_t
#endif

static std::string
_get_program_file_name(_In_z_ const char* base_file_name, ebpf_execution_type_t execution_type)
{
    std::string file_name = base_file_name;
    if (execution_type == EBPF_EXECUTION_NATIVE) {
        file_name += EBPF_PROGRAM_FILE_EXTENSION_NATIVE;
    } else {
        file_name += EBPF_PROGRAM_FILE_EXTENSION_JIT;
    }
    return file_name;
}

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

    const char* program_file_name = nullptr;
    const char* program_section_name = nullptr;
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

    ebpf_free_string(program_file_name);
    ebpf_free_string(program_section_name);

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
    test_program_next_previous("test_sample_ebpf.sys", SAMPLE_PROGRAM_COUNT);
    test_program_next_previous("bindmonitor.sys", BIND_MONITOR_PROGRAM_COUNT);
}

TEST_CASE("test_ebpf_map_next_previous_native", "[test_ebpf_map_next_previous]")
{
    test_map_next_previous("test_sample_ebpf.sys", SAMPLE_MAP_COUNT);
    test_map_next_previous("bindmonitor.sys", BIND_MONITOR_MAP_COUNT);
}

// Synchronous ring buffer API test function.
TEMPLATE_TEST_CASE("ring_buffer_sync_api", "[ring_buffer]", ENABLED_EXECUTION_TYPES)
{
    ebpf_execution_type_t execution_type = TestType::value;
    std::string file_name = _get_program_file_name("bindmonitor_ringbuf", execution_type);
    const uint16_t base_test_port = 12300;
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper;
    _helper.initialize(file_name.c_str(), BPF_PROG_TYPE_BIND, "bind_monitor", execution_type, nullptr, 0, hook);
    object = _helper.get_object();

    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    REQUIRE(process_map_fd > 0);

    // Create a synchronous ring buffer (default mode without auto-callback flag).
    ebpf_ring_buffer_opts ring_opts{.sz = sizeof(ring_opts), .flags = 0};

    uint32_t event_count = 0;
    const uint32_t expected_events = 10;

    auto ring = ebpf_ring_buffer__new(
        process_map_fd,
        [](void* ctx, void* /*data*/, size_t /*size */) {
            uint32_t* count = reinterpret_cast<uint32_t*>(ctx);
            (*count)++;
            return 0;
        },
        &event_count,
        &ring_opts);
    REQUIRE(ring != nullptr);

    // Test ebpf_ring_buffer_get_wait_handle.
    ebpf_handle_t wait_handle = ebpf_ring_buffer_get_wait_handle(ring);
    REQUIRE(wait_handle != ebpf_handle_invalid);

    // Generate event to consume by triggering socket bind.
    perform_socket_bind(base_test_port, true);

    // Test 1: Use WaitForSingleObject and consume to verify we can consume after notify.
    DWORD wait_result = WaitForSingleObject(reinterpret_cast<HANDLE>(wait_handle), 5000); // 5 second timeout.
    REQUIRE(wait_result == WAIT_OBJECT_0);

    int consume_result = ring_buffer__consume(ring);
    REQUIRE(consume_result > 0);
    REQUIRE(event_count > 0);

    // Generate some additional events.
    for (uint16_t i = 1; i < expected_events; i++) {
        perform_socket_bind(base_test_port + i, true);
    }

    // Test 2: Use poll API in a loop until we get all expected events.
    int total_events_polled = 0;
    int max_iterations = 20;
    int iteration = 0;

    while (event_count < expected_events && iteration < max_iterations) {
        int poll_result = ring_buffer__poll(ring, 200); // 200ms timeout.
        REQUIRE(poll_result >= 0);

        if (poll_result == 0) {
            // Timeout - no events available right now.
            iteration++;
            continue;
        }

        total_events_polled += poll_result;
        iteration++;
    }

    REQUIRE(total_events_polled > 0);
    REQUIRE(event_count >= expected_events);

    // Clean up.
    ring_buffer__free(ring);
}

// Test synchronous ring buffer consume API.
TEST_CASE("ring_buffer_sync_consume", "[ring_buffer]")
{
    // Create a ring buffer map for testing.
    fd_t map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "test_ringbuf", 0, 0, 64 * 1024, nullptr);
    REQUIRE(map_fd > 0);

    // Create synchronous ring buffer.
    ebpf_ring_buffer_opts ring_opts = {.sz = sizeof(ring_opts), .flags = 0};

    struct test_context
    {
        uint32_t event_count = 0;
        std::vector<std::string> received_data;
    };
    test_context context;

    auto ring = ebpf_ring_buffer__new(
        map_fd,
        [](void* ctx, void* data, size_t size) {
            auto* test_ctx = reinterpret_cast<test_context*>(ctx);
            std::string record_data(reinterpret_cast<const char*>(data), size);
            test_ctx->received_data.push_back(record_data);
            test_ctx->event_count++;
            return 0;
        },
        &context,
        &ring_opts);
    REQUIRE(ring != nullptr);

    // Test ebpf_ring_buffer_get_buffer with index 0.
    const ebpf_ring_buffer_producer_page_t* producer_ptr = nullptr;
    ebpf_ring_buffer_consumer_page_t* consumer_ptr = nullptr;
    const uint8_t* data_ptr = nullptr;
    uint64_t data_size = 0;

    ebpf_result_t result = ebpf_ring_buffer_get_buffer(ring, 0, &consumer_ptr, &producer_ptr, &data_ptr, &data_size);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(producer_ptr != nullptr);
    REQUIRE(consumer_ptr != nullptr);
    REQUIRE(data_ptr != nullptr);
    REQUIRE(data_size > 0);

    // Write test data to the ring buffer.
    std::vector<std::string> test_messages = {"First message", "Second message", "Third message"};

    for (const auto& msg : test_messages) {
        result = ebpf_ring_buffer_map_write(map_fd, msg.c_str(), msg.length());
        REQUIRE(result == EBPF_SUCCESS);
    }

    // Use ring_buffer__consume to process all available events.
    int consume_result = ring_buffer__consume(ring);
    REQUIRE(consume_result >= 0);

    // Verify we received all the test messages.
    REQUIRE(context.event_count == test_messages.size());
    REQUIRE(context.received_data.size() == test_messages.size());

    for (size_t i = 0; i < test_messages.size(); i++) {
        REQUIRE(context.received_data[i] == test_messages[i]);
    }

    // Clean up.
    ring_buffer__free(ring);
    _close(map_fd);
}

// Test synchronous ring buffer with multiple maps.
TEST_CASE("ring_buffer_sync_multiple_maps", "[ring_buffer]")
{
    fd_t map_fd1 = -1;
    fd_t map_fd2 = -1;
    ring_buffer* ring = nullptr;
    auto cleanup = std::unique_ptr<void, std::function<void(void*)>>(
        reinterpret_cast<void*>(1), // Dummy pointer, we only care about the deleter.
        [&](void*) {
            // Cleanup - in unique_ptr scope guard to ensure cleanup on failure.
            if (ring != nullptr) {
                ring_buffer__free(ring);
            }
            if (map_fd1 > 0) {
                _close(map_fd1);
            }
            if (map_fd2 > 0) {
                _close(map_fd2);
            }
        });
    // Create multiple ring buffer maps for testing.
    map_fd1 = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "test_ringbuf1", 0, 0, 32 * 1024, nullptr);
    REQUIRE(map_fd1 > 0);

    map_fd2 = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "test_ringbuf2", 0, 0, 32 * 1024, nullptr);
    REQUIRE(map_fd2 > 0);

    // Create synchronous ring buffer with first map.
    ebpf_ring_buffer_opts ring_opts = {.sz = sizeof(ring_opts), .flags = 0};

    struct multi_map_context
    {
        uint32_t event_count = 0;
        std::vector<std::string> received_data;
    };
    multi_map_context context;

    ring = ebpf_ring_buffer__new(
        map_fd1,
        [](void* ctx, void* data, size_t size) {
            auto* test_ctx = reinterpret_cast<multi_map_context*>(ctx);
            std::string record_data(reinterpret_cast<const char*>(data), size);
            test_ctx->received_data.push_back(record_data);
            test_ctx->event_count++;
            return 0;
        },
        &context,
        &ring_opts);
    REQUIRE(ring != nullptr);

    // Add second map to the ring buffer.
    int add_result = ring_buffer__add(
        ring,
        map_fd2,
        [](void* ctx, void* data, size_t size) {
            auto* test_ctx = reinterpret_cast<multi_map_context*>(ctx);
            std::string record_data(reinterpret_cast<const char*>(data), size);
            test_ctx->received_data.push_back(record_data);
            test_ctx->event_count++;
            return 0;
        },
        &context);
    REQUIRE(add_result == 0);

    // Test ebpf_ring_buffer_get_wait_handle for shared wait handle.
    ebpf_handle_t wait_handle = ebpf_ring_buffer_get_wait_handle(ring);
    REQUIRE(wait_handle != ebpf_handle_invalid);

    // Test ebpf_ring_buffer_get_buffer for each map.
    for (int i = 0; i < 2; i++) {
        const ebpf_ring_buffer_producer_page_t* producer_ptr = nullptr;
        ebpf_ring_buffer_consumer_page_t* consumer_ptr = nullptr;
        const uint8_t* data_ptr = nullptr;
        uint64_t data_size = 0;

        ebpf_result_t result =
            ebpf_ring_buffer_get_buffer(ring, i, &consumer_ptr, &producer_ptr, &data_ptr, &data_size);
        REQUIRE(result == EBPF_SUCCESS);
        REQUIRE(producer_ptr != nullptr);
        REQUIRE(consumer_ptr != nullptr);
        REQUIRE(data_ptr != nullptr);
        REQUIRE(data_size > 0);
    }

    // Test invalid index.
    {
        const ebpf_ring_buffer_producer_page_t* producer_ptr = nullptr;
        ebpf_ring_buffer_consumer_page_t* consumer_ptr = nullptr;
        const uint8_t* data_ptr = nullptr;
        uint64_t data_size = 0;

        ebpf_result_t result =
            ebpf_ring_buffer_get_buffer(ring, 2, &consumer_ptr, &producer_ptr, &data_ptr, &data_size);
        REQUIRE(result == EBPF_OBJECT_NOT_FOUND);
    }

    // Write test data to both ring buffers.
    std::string msg1 = "Message from map1";
    std::string msg2 = "Message from map2";

    ebpf_result_t result1 = ebpf_ring_buffer_map_write(map_fd1, msg1.c_str(), msg1.length());
    REQUIRE(result1 == EBPF_SUCCESS);

    ebpf_result_t result2 = ebpf_ring_buffer_map_write(map_fd2, msg2.c_str(), msg2.length());
    REQUIRE(result2 == EBPF_SUCCESS);

    // Use ring_buffer__consume to process all available events.
    int consume_result = ring_buffer__consume(ring);
    REQUIRE(consume_result >= 0);

    // Verify we received messages from both maps.
    REQUIRE(context.event_count == 2);
    REQUIRE(context.received_data.size() == 2);

    // Check that we got data from both maps.
    bool found_map1 = false, found_map2 = false;
    for (const auto& data : context.received_data) {
        if (data == msg1)
            found_map1 = true;
        if (data == msg2)
            found_map2 = true;
    }
    REQUIRE(found_map1);
    REQUIRE(found_map2);
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
        REQUIRE(0 < found_value.start_key);

        // For TCP connections, the hook may run on a worker thread/process, not the caller process.
        // For UDP connections, the hook runs synchronously on the caller process.
        if (protocol == IPPROTO_TCP) {
            // For TCP, verify that the PID is valid (non-zero) rather than matching the test process.
            REQUIRE(found_value.current_pid > 0);
        } else {
            // For UDP, verify exact match since the hook runs synchronously.
            unsigned long pid = GetCurrentProcessId();
            REQUIRE(pid == found_value.current_pid);
        }
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

        // Verify thread ID and start time values.
        // For TCP connections, the hook may run on a worker thread, not the caller thread.
        // For UDP connections, the hook runs synchronously on the caller thread.
        if (protocol == IPPROTO_TCP) {
            // For TCP, verify that the thread ID is valid (non-zero) rather than matching a specific value.
            REQUIRE(found_value.current_tid > 0);
            // For TCP, verify that the start time is valid (non-zero).
            REQUIRE(found_value.start_time > 0);
        } else {
            // For UDP, verify exact match since the hook runs synchronously.
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
    struct bpf_object* object = nullptr;
    struct bpf_object* object2 = nullptr;
    fd_t program_fd;
    const char* file_name = "bindmonitor.sys";

    result = program_load_helper(file_name, BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object, &program_fd, false);
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
    result = program_load_helper(file_name, BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object2, &program_fd, false);
    REQUIRE(result == -ENOENT);

    // Close the native module handle. That should result in the module to be unloaded.
    REQUIRE(_close(native_module_fd) == 0);
    object->native_module_fd = ebpf_fd_invalid;

    // Add a sleep to allow the previous driver to be unloaded successfully.
    Sleep(1000);

    // Try to load the same native module again. It should succeed this time.
    object2 = nullptr;
    result = program_load_helper(file_name, BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object2, &program_fd, false);
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

    REQUIRE(
        program_load_helper(
            "bindmonitor_ringbuf.sys", BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object, &program_fd) == 0);

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

    REQUIRE(
        program_load_helper(
            "bindmonitor_ringbuf.sys", BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object, &program_fd) == 0);

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

// Context structure for perf buffer test callbacks.
typedef struct _perf_buffer_sync_test_context
{
    std::atomic<uint64_t> event_count{0};
    std::atomic<uint64_t> lost_count{0};
    std::vector<std::string> received_data;
    std::mutex lock;
    bool keep_records{true};

    // Blocking support (used by perf_buffer_sync_callback_block test).
    std::mutex* block_mutex{nullptr};
    std::condition_variable* block_cv{nullptr};
    std::atomic<bool> block_callback{false};

    // Async completion support.
    uint64_t expected_event_count{0};
    std::promise<void>* completion_promise{nullptr};
} perf_buffer_sync_test_context_t;

// Signal async completion promise if total events (received + lost) reached the target.
static void
_try_notify_completion(_In_ perf_buffer_sync_test_context_t* context)
{
    if (context->completion_promise == nullptr) {
        return;
    }
    uint64_t total =
        context->event_count.load(std::memory_order_relaxed) + context->lost_count.load(std::memory_order_relaxed);
    if (total >= context->expected_event_count) {
        try {
            context->completion_promise->set_value();
        } catch (const std::future_error& e) {
            if (e.code() != std::future_errc::promise_already_satisfied) {
                throw;
            }
        }
    }
}

static void
perf_buffer_sync_sample_callback(_In_ void* ctx, int cpu, _In_reads_bytes_(size) void* data, uint32_t size)
{
    UNREFERENCED_PARAMETER(cpu);
    auto* context = reinterpret_cast<perf_buffer_sync_test_context_t*>(ctx);

    // Optional blocking for stress tests.
    if (context->block_callback.load(std::memory_order_acquire) && context->block_mutex && context->block_cv) {
        std::unique_lock<std::mutex> lock(*context->block_mutex);
        while (context->block_callback.load(std::memory_order_acquire)) {
            context->block_cv->wait_for(lock, std::chrono::milliseconds(500));
        }
    }

    if (context->keep_records && data != nullptr && size > 0) {
        std::lock_guard<std::mutex> guard(context->lock);
        context->received_data.emplace_back(reinterpret_cast<const char*>(data), size);
    }

    context->event_count.fetch_add(1, std::memory_order_relaxed);
    _try_notify_completion(context);
}

static void
perf_buffer_sync_lost_callback(_In_ void* ctx, int cpu, uint64_t count)
{
    UNREFERENCED_PARAMETER(cpu);
    auto* context = reinterpret_cast<perf_buffer_sync_test_context_t*>(ctx);
    context->lost_count.fetch_add(count, std::memory_order_relaxed);
    _try_notify_completion(context);
}

/**
 * @brief RAII helper for perf buffer tests.
 *
 * Manages perf buffer and map resources with automatic cleanup, provides shared callbacks
 * and context, and implements common test patterns (polling, validation, async completion).
 */
class perf_buffer_test_helper
{
  public:
    perf_buffer_sync_test_context_t context{};

    perf_buffer_test_helper(bool keep_records = true) { context.keep_records = keep_records; }

    ~perf_buffer_test_helper() { cleanup(); }

    perf_buffer_test_helper(const perf_buffer_test_helper&) = delete;
    perf_buffer_test_helper&
    operator=(const perf_buffer_test_helper&) = delete;

    /**
     * @brief Create a perf buffer with RAII cleanup. Pass EBPF_PERFBUF_FLAG_AUTO_CALLBACK in flags for async mode.
     */
    perf_buffer*
    create_perf_buffer(fd_t map_fd, uint32_t flags = 0)
    {
        REQUIRE(_buffer == nullptr);
        ebpf_perf_buffer_opts opts = {.sz = sizeof(opts), .flags = flags};
        _buffer = ebpf_perf_buffer__new(
            map_fd, 0, perf_buffer_sync_sample_callback, perf_buffer_sync_lost_callback, &context, &opts);
        return _buffer;
    }

    /**
     * @brief Create a perf event array map and register it for RAII cleanup.
     *
     * @return 0 on success, -errno on failure.
     */
    int
    initialize_map(fd_t& map_fd, _In_opt_z_ const char* name = nullptr, uint32_t max_entries = 0)
    {
        uint32_t entries = max_entries > 0 ? max_entries : static_cast<uint32_t>(libbpf_num_possible_cpus());
        map_fd = bpf_map_create(BPF_MAP_TYPE_PERF_EVENT_ARRAY, name, 0, 0, entries, nullptr);
        if (map_fd > 0) {
            REQUIRE(_map_fd == ebpf_fd_invalid);
            _map_fd = map_fd;
            return 0;
        }
        return -errno;
    }

    /**
     * @brief Poll until (event_count + lost_count) >= expected_total or timeout.
     *
     * @param[in] pb Perf buffer to poll.
     * @param[in] expected_total Target total event count (received + lost).
     * @param[in] poll_timeout_ms Timeout per poll call in milliseconds.
     * @param[in] overall_timeout Overall timeout for the polling loop.
     * @return Total number of events polled (not including lost events).
     */
    int
    poll_until_count(
        _In_ perf_buffer* pb,
        uint64_t expected_total,
        int poll_timeout_ms = 200,
        std::chrono::milliseconds overall_timeout = std::chrono::seconds(10))
    {
        int total_polled = 0;
        auto start_time = std::chrono::steady_clock::now();

        while ((context.event_count + context.lost_count) < expected_total) {
            if ((std::chrono::steady_clock::now() - start_time) >= overall_timeout) {
                break;
            }
            int poll_result = perf_buffer__poll(pb, poll_timeout_ms);
            REQUIRE(poll_result >= 0);
            if (poll_result > 0) {
                total_polled += poll_result;
            }
        }
        return total_polled;
    }

    /**
     * @brief Set callback blocking flag. The sample callback will block until unblock_callback() is called.
     */
    void
    block_callback()
    {
        if (context.block_mutex == nullptr) {
            context.block_mutex = &_block_mutex;
            context.block_cv = &_block_cv;
        }
        context.block_callback.store(true, std::memory_order_release);
    }

    /**
     * @brief Clear callback blocking flag and wake any blocked callbacks.
     */
    void
    unblock_callback()
    {
        if (context.block_cv) {
            std::lock_guard<std::mutex> lock(_block_mutex);
            context.block_callback.store(false, std::memory_order_release);
            context.block_cv->notify_all();
        } else {
            context.block_callback.store(false, std::memory_order_release);
        }
    }

    /**
     * @brief Set up promise/future for async completion when (event_count + lost_count) >= expected_events.
     *
     * @param[in] expected_events Target event count to trigger completion.
     */
    std::future<void>
    enable_async_completion(uint64_t expected_events)
    {
        context.expected_event_count = expected_events;
        context.completion_promise = &_completion_promise;
        return _completion_promise.get_future();
    }

    /**
     * @brief Verify received data matches expected messages in order.
     *
     * @param[in] expected_messages Expected messages in order.
     */
    void
    validate_data(_In_ const std::vector<std::string>& expected_messages)
    {
        std::lock_guard<std::mutex> guard(context.lock);
        REQUIRE(context.received_data.size() == expected_messages.size());
        for (size_t i = 0; i < expected_messages.size(); i++) {
            REQUIRE(context.received_data[i] == expected_messages[i]);
        }
    }

    /**
     * @brief Verify received data contains the expected messages (order-independent).
     *
     * Use this when writes may land on different CPUs, since perf event arrays
     * are per-CPU and cross-CPU ordering is not guaranteed.
     *
     * @param[in] expected_messages Expected messages (any order).
     */
    void
    validate_data_unordered(_In_ const std::vector<std::string>& expected_messages)
    {
        std::lock_guard<std::mutex> guard(context.lock);
        REQUIRE(context.received_data.size() == expected_messages.size());
        auto sorted_received = context.received_data;
        auto sorted_expected = expected_messages;
        std::sort(sorted_received.begin(), sorted_received.end());
        std::sort(sorted_expected.begin(), sorted_expected.end());
        for (size_t i = 0; i < sorted_expected.size(); i++) {
            REQUIRE(sorted_received[i] == sorted_expected[i]);
        }
    }

  private:
    perf_buffer* _buffer = nullptr;
    fd_t _map_fd = ebpf_fd_invalid;
    std::mutex _block_mutex;
    std::condition_variable _block_cv;
    std::promise<void> _completion_promise;

    void
    cleanup()
    {
        if (_buffer != nullptr) {
            perf_buffer__free(_buffer);
            _buffer = nullptr;
        }
        if (_map_fd > 0) {
            _close(_map_fd);
            _map_fd = ebpf_fd_invalid;
        }
    }
};

// Async stress test using EBPF_PERFBUF_FLAG_AUTO_CALLBACK mode.
// This test validates that the async callback mechanism correctly handles high-volume
// event generation across multiple CPUs without requiring manual polling.
TEST_CASE("perf_buffer_async_consumer", "[stress][perf_buffer]")
{
    // Load bindmonitor_perf_event_array.sys.
    struct bpf_object* object = nullptr;
    fd_t program_fd = ebpf_fd_invalid;
    std::string app_id = "api_test.exe";
    uint32_t cpu_count = libbpf_num_possible_cpus();
    CAPTURE(cpu_count);

    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor_perf_event_array", EBPF_EXECUTION_NATIVE);

    REQUIRE(
        program_load_helper(
            "bindmonitor_perf_event_array.sys", BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object, &program_fd) == 0);

    // RAII cleanup for program object. Declared before helper so bpf_object outlives the perf buffer
    // (perf_buffer__free uses map_fd for IOCTLs, and bpf_object__close closes the map fd).
    auto object_cleanup = std::unique_ptr<bpf_object, decltype(&bpf_object__close)>(object, bpf_object__close);

    // Get fd of process_map map.
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");

    uint32_t max_entries = bpf_map__max_entries(bpf_object__find_map_by_name(object, "process_map"));
    uint32_t max_iterations = static_cast<uint32_t>(10 * (max_entries / app_id.size()));
    CAPTURE(max_entries, max_iterations);

    // Set up helper with async completion support (don't keep records for stress test).
    perf_buffer_test_helper helper(false);
    auto completion_future = helper.enable_async_completion(max_iterations);

    // Create perf buffer in async mode (EBPF_PERFBUF_FLAG_AUTO_CALLBACK).
    auto* pb = helper.create_perf_buffer(process_map_fd, EBPF_PERFBUF_FLAG_AUTO_CALLBACK);
    REQUIRE(pb != nullptr);

    // Trigger perf buffer events from multiple threads across all CPUs.
    trigger_ring_buffer_events(program_fd, max_iterations, app_id.data(), static_cast<uint32_t>(app_id.size()));

    // Wait for 1 second for async callbacks to process all events.
    REQUIRE(completion_future.wait_for(1s) == std::future_status::ready);

    CAPTURE(helper.context.event_count, max_iterations, helper.context.lost_count);
    // trigger_ring_buffer_events rounds up per-thread work, so total events may exceed max_iterations.
    REQUIRE((helper.context.event_count + helper.context.lost_count) >= max_iterations);
}

// Async test: Consume events with async callbacks and validate data ordering.
// Equivalent to perf_buffer_sync_consume but uses EBPF_PERFBUF_FLAG_AUTO_CALLBACK.
TEST_CASE("perf_buffer_async_consume", "[perf_buffer]")
{
    // Create perf event array map.
    perf_buffer_test_helper helper(true); // Keep records to validate data
    fd_t map_fd;
    REQUIRE(helper.initialize_map(map_fd, "test_perfbuf", 64 * 1024) == 0);

    // Prepare test messages.
    std::vector<std::string> test_messages = {"Message 1", "Message 2", "Message 3", "Message 4", "Message 5"};

    // Enable async completion and create perf buffer in async mode.
    auto completion_future = helper.enable_async_completion(static_cast<uint32_t>(test_messages.size()));
    auto* pb = helper.create_perf_buffer(map_fd, EBPF_PERFBUF_FLAG_AUTO_CALLBACK);
    REQUIRE(pb != nullptr);

    // Write all test events.
    size_t written = 0;
    for (const auto& msg : test_messages) {
        if (ebpf_perf_event_array_map_write(map_fd, msg.c_str(), msg.length()) == EBPF_SUCCESS) {
            written++;
        }
    }
    REQUIRE(written == test_messages.size());

    // Wait for async callbacks to process all events.
    REQUIRE(completion_future.wait_for(5s) == std::future_status::ready);

    // Validate all events were received.
    REQUIRE(helper.context.event_count == test_messages.size());
    REQUIRE(helper.context.lost_count == 0);

    // Validate data matches expected messages (order not guaranteed across CPUs).
    helper.validate_data_unordered(test_messages);
}

// Async test: Validate lost event callback in async mode.
// Equivalent to perf_buffer_sync_lost_callback but uses EBPF_PERFBUF_FLAG_AUTO_CALLBACK.
TEST_CASE("perf_buffer_async_lost_callback", "[perf_buffer]")
{
    // Create perf event array map with small buffer to trigger overflow.
    perf_buffer_test_helper helper(false); // Don't keep records for overflow test
    fd_t map_fd;
    REQUIRE(helper.initialize_map(map_fd, "test_perfbuf", 16 * 1024) == 0);

    // Use 504-byte messages (512 with header) to precisely fill the 16KB per-CPU ring.
    const size_t large_event_size = 504;
    const size_t events_per_ring = 16 * 1024 / 512;         // 32 records of 512 bytes (504 + 8-byte header) fit.
    const size_t per_cpu_event_count = 2 * events_per_ring; // Write 2x capacity to overflow by exactly half.
    uint32_t num_cpus = static_cast<uint32_t>(libbpf_num_possible_cpus());
    uint32_t total_events = static_cast<uint32_t>(per_cpu_event_count * num_cpus);
    std::string large_message(large_event_size, 'X');

    // Enable async completion and create perf buffer in async mode.
    auto completion_future = helper.enable_async_completion(total_events);
    auto* pb = helper.create_perf_buffer(map_fd, EBPF_PERFBUF_FLAG_AUTO_CALLBACK);
    REQUIRE(pb != nullptr);

    // Block the async callback so events accumulate and overflow the buffer.
    helper.block_callback();

    // Write events per-CPU using affinity to overflow each ring.
    size_t write_succeeded = 0;
    size_t write_failed = 0;
    scoped_cpu_affinity cpu_affinity{};
    for (uint32_t cpu_id = 0; cpu_id < num_cpus; cpu_id++) {
        cpu_affinity.switch_cpu(cpu_id);
        for (size_t i = 0; i < per_cpu_event_count; i++) {
            if (ebpf_perf_event_array_map_write(map_fd, large_message.c_str(), large_message.length()) ==
                EBPF_SUCCESS) {
                write_succeeded++;
            } else {
                write_failed++;
            }
        }
    }

    // Unblock callback to let async processing drain all events.
    helper.unblock_callback();

    // Wait for async callbacks to process events (some will be lost).
    REQUIRE(completion_future.wait_for(5s) == std::future_status::ready);

    // Validate exact event counts: each 16KB per-CPU ring holds exactly 32 records.
    uint32_t expected_lost = static_cast<uint32_t>(events_per_ring * num_cpus);
    REQUIRE(write_succeeded == events_per_ring * num_cpus);
    REQUIRE(write_failed == events_per_ring * num_cpus);
    REQUIRE(helper.context.lost_count == expected_lost);
    REQUIRE(helper.context.event_count == expected_lost);
    REQUIRE((helper.context.event_count + helper.context.lost_count) == total_events);
}

// Test synchronous perf buffer API with real program.
TEMPLATE_TEST_CASE("perf_buffer_sync_api", "[perf_buffer]", ENABLED_EXECUTION_TYPES)
{
    ebpf_execution_type_t execution_type = TestType::value;
    std::string file_name = _get_program_file_name("bindmonitor_perf_event_array", execution_type);
    const uint16_t base_test_port = 12400;
    struct bpf_object* object = nullptr;
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t _helper;
    _helper.initialize(file_name.c_str(), BPF_PROG_TYPE_BIND, "bind_monitor", execution_type, nullptr, 0, hook);
    object = _helper.get_object();

    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    REQUIRE(process_map_fd > 0);

    perf_buffer_test_helper helper(false); // Don't keep records for this test

    // Create a synchronous perf buffer.
    auto pb = helper.create_perf_buffer(process_map_fd);
    REQUIRE(pb != nullptr);

    // Test ebpf_perf_buffer_get_wait_handle.
    ebpf_handle_t wait_handle = ebpf_perf_buffer_get_wait_handle(pb);
    REQUIRE(wait_handle != ebpf_handle_invalid);

    // Test perf_buffer__buffer_cnt matches CPU count.
    size_t buffer_cnt = perf_buffer__buffer_cnt(pb);
    int cpu_count = libbpf_num_possible_cpus();
    REQUIRE(cpu_count > 0);
    REQUIRE(buffer_cnt == static_cast<size_t>(cpu_count));

    // Generate event to consume by triggering socket bind.
    perform_socket_bind(base_test_port, true);

    // Test 1: Use WaitForSingleObject and consume to verify we can consume after notify.
    DWORD wait_result = WaitForSingleObject(reinterpret_cast<HANDLE>(wait_handle), 5000);
    REQUIRE(wait_result == WAIT_OBJECT_0);

    // The BPF bind monitor may emit multiple perf events per socket bind (e.g. bind + unbind).
    int consume_result = perf_buffer__consume(pb);
    REQUIRE(consume_result > 0);
    REQUIRE(helper.context.event_count > 0);

    // Generate some additional events.
    const uint32_t expected_events = 10;
    for (uint16_t i = 1; i < expected_events; i++) {
        perform_socket_bind(base_test_port + i, true);
    }

    // Test 2: Use poll API until we get all expected events.
    int total_events_polled = helper.poll_until_count(pb, expected_events);
    REQUIRE(total_events_polled > 0);
    REQUIRE(helper.context.event_count >= expected_events);
}

// Test synchronous perf buffer consume API with manually created map.
TEST_CASE("perf_buffer_sync_consume", "[perf_buffer]")
{
    perf_buffer_test_helper helper;

    // Create a perf event array map for testing.
    fd_t map_fd;
    REQUIRE(helper.initialize_map(map_fd, "test_perfbuf", 64 * 1024) == 0);

    // Create synchronous perf buffer.
    auto pb = helper.create_perf_buffer(map_fd);
    REQUIRE(pb != nullptr);

    // Test perf_buffer__buffer_cnt matches CPU count.
    size_t buffer_cnt = perf_buffer__buffer_cnt(pb);
    int cpu_count = libbpf_num_possible_cpus();
    REQUIRE(cpu_count > 0);
    REQUIRE(buffer_cnt == static_cast<size_t>(cpu_count));

    // Write test data to the perf event array.
    std::vector<std::string> test_messages = {"First perf message", "Second perf message", "Third perf message"};
    size_t written = 0;
    for (const auto& msg : test_messages) {
        if (ebpf_perf_event_array_map_write(map_fd, msg.c_str(), msg.length()) == EBPF_SUCCESS) {
            written++;
        }
    }
    REQUIRE(written == test_messages.size());

    // Use perf_buffer__consume to process all available events.
    int consume_result = perf_buffer__consume(pb);
    REQUIRE(consume_result == static_cast<int>(test_messages.size()));

    // Verify we received the test messages (order not guaranteed across CPUs).
    REQUIRE(helper.context.event_count == test_messages.size());
    helper.validate_data_unordered(test_messages);
}

// Test synchronous perf buffer with per-CPU buffer consumption.
TEST_CASE("perf_buffer_sync_multiple_cpus", "[perf_buffer]")
{
    perf_buffer_test_helper helper(false); // Don't keep records

    // Create a perf event array map for testing.
    fd_t map_fd;
    REQUIRE(helper.initialize_map(map_fd, "test_perfbuf", 64 * 1024) == 0);

    // Create synchronous perf buffer.
    auto pb = helper.create_perf_buffer(map_fd);
    REQUIRE(pb != nullptr);

    // Verify buffer count matches CPU count.
    size_t buffer_cnt = perf_buffer__buffer_cnt(pb);
    int cpu_count = libbpf_num_possible_cpus();
    REQUIRE(cpu_count > 0);
    REQUIRE(buffer_cnt == static_cast<size_t>(cpu_count));

    // Test perf_buffer__consume_buffer for each CPU.
    for (size_t i = 0; i < buffer_cnt; i++) {
        int consume_result = perf_buffer__consume_buffer(pb, i);
        REQUIRE(consume_result == 0); // No data yet.
    }

    // Test invalid CPU index.
    int invalid_result = perf_buffer__consume_buffer(pb, buffer_cnt + 100);
    REQUIRE(invalid_result == -EINVAL);

    // Write test data.
    const std::string msg = "Test message for CPU buffers";
    ebpf_result_t write_result = ebpf_perf_event_array_map_write(map_fd, msg.c_str(), msg.length());
    REQUIRE(write_result == EBPF_SUCCESS);

    // Use perf_buffer__consume to process all CPU buffers.
    int consume_result = perf_buffer__consume(pb);
    REQUIRE(consume_result == 1);

    // Verify we received the message.
    REQUIRE(helper.context.event_count == 1);
}

// Test synchronous perf buffer poll timeout behavior.
TEST_CASE("perf_buffer_sync_poll_timeout", "[perf_buffer]")
{
    perf_buffer_test_helper helper(false); // Don't keep records

    // Create a perf event array map for testing.
    fd_t map_fd;
    REQUIRE(helper.initialize_map(map_fd, "test_perfbuf", 64 * 1024) == 0);

    // Create synchronous perf buffer.
    auto pb = helper.create_perf_buffer(map_fd);
    REQUIRE(pb != nullptr);

    // Test poll with timeout 0 (non-blocking) - should return immediately with 0.
    auto start = std::chrono::steady_clock::now();
    int poll_result = perf_buffer__poll(pb, 0);
    auto elapsed = std::chrono::steady_clock::now() - start;
    REQUIRE(poll_result == 0);
    // Non-blocking poll should return near-instantly; 100ms is a generous scheduling margin.
    REQUIRE(elapsed < std::chrono::milliseconds(100));

    // Test poll with small timeout - should wait and return 0.
    start = std::chrono::steady_clock::now();
    poll_result = perf_buffer__poll(pb, 100);
    elapsed = std::chrono::steady_clock::now() - start;
    REQUIRE(poll_result == 0);
    // poll(100ms) should wait at least half the timeout, accounting for OS scheduling variance.
    REQUIRE(elapsed >= std::chrono::milliseconds(50));

    // Write data and verify poll returns positive.
    const std::string msg = "Test poll message";
    ebpf_result_t write_result = ebpf_perf_event_array_map_write(map_fd, msg.c_str(), msg.length());
    REQUIRE(write_result == EBPF_SUCCESS);

    poll_result = perf_buffer__poll(pb, 1000);
    REQUIRE(poll_result == 1);
    REQUIRE(helper.context.event_count == 1);
}

// Test synchronous perf buffer wait handle behavior.
TEST_CASE("perf_buffer_sync_wait_handle", "[perf_buffer]")
{
    // Create a perf event array map with RAII cleanup (outlives both helper scopes below).
    perf_buffer_test_helper map_owner(false);
    fd_t map_fd;
    REQUIRE(map_owner.initialize_map(map_fd, "test_perfbuf", 64 * 1024) == 0);

    // Test sync mode - should have valid wait handle.
    {
        perf_buffer_test_helper helper(false);
        auto pb = helper.create_perf_buffer(map_fd);
        REQUIRE(pb != nullptr);

        ebpf_handle_t wait_handle = ebpf_perf_buffer_get_wait_handle(pb);
        REQUIRE(wait_handle != ebpf_handle_invalid);

        // Wait handle should be in non-signaled state initially (no data).
        DWORD wait_result = WaitForSingleObject(reinterpret_cast<HANDLE>(wait_handle), 0);
        REQUIRE(wait_result == WAIT_TIMEOUT);

        // Write data - wait handle should become signaled.
        const std::string msg = "Test wait handle";
        ebpf_result_t write_result = ebpf_perf_event_array_map_write(map_fd, msg.c_str(), msg.length());
        REQUIRE(write_result == EBPF_SUCCESS);

        wait_result = WaitForSingleObject(reinterpret_cast<HANDLE>(wait_handle), 5000);
        REQUIRE(wait_result == WAIT_OBJECT_0);
    }

    // Test async mode - should have invalid wait handle.
    {
        perf_buffer_test_helper helper(false);
        auto pb = helper.create_perf_buffer(map_fd, EBPF_PERFBUF_FLAG_AUTO_CALLBACK);
        REQUIRE(pb != nullptr);

        ebpf_handle_t wait_handle = ebpf_perf_buffer_get_wait_handle(pb);
        REQUIRE(wait_handle == ebpf_handle_invalid);
    }
}

// Test synchronous perf buffer lost callback.
TEST_CASE("perf_buffer_sync_lost_callback", "[perf_buffer]")
{
    perf_buffer_test_helper helper;

    // Create a small perf event array map to trigger overflow.
    fd_t map_fd;
    REQUIRE(helper.initialize_map(map_fd, "test_perfbuf", 16 * 1024) == 0);

    // Create synchronous perf buffer.
    auto pb = helper.create_perf_buffer(map_fd);
    REQUIRE(pb != nullptr);

    // Verify initial state.
    REQUIRE(helper.context.lost_count == 0);
    REQUIRE(helper.context.event_count == 0);

    size_t writes_attempted = 0;
    size_t failed_writes = 0;

    // Write normal event and consume successfully.
    const std::string first_msg = "Test lost callback";
    ebpf_result_t write_result = ebpf_perf_event_array_map_write(map_fd, first_msg.c_str(), first_msg.length());
    writes_attempted++;
    REQUIRE(write_result == EBPF_SUCCESS);

    int consume_result = perf_buffer__consume(pb);
    REQUIRE(consume_result == 1);
    REQUIRE(helper.context.event_count == 1);
    REQUIRE(helper.context.lost_count == 0);

    // Trigger lost events by filling the buffer beyond capacity.
    // Each 16KB per-CPU ring holds exactly 32 records of 512 bytes (504 data + 8-byte header).
    const size_t large_event_size = 504;
    const size_t events_per_ring = 16 * 1024 / 512;         // 32 records fit per CPU ring.
    const size_t per_cpu_event_count = 2 * events_per_ring; // Write 2x capacity to overflow by exactly half.
    std::vector<std::string> large_messages(per_cpu_event_count, std::string(large_event_size, 'X'));

    // Loop over CPUs, setting CPU affinity to overflow each ring.
    scoped_cpu_affinity cpu_affinity{};
    for (uint32_t cpu_id = 0; cpu_id < static_cast<uint32_t>(libbpf_num_possible_cpus()); cpu_id++) {
        cpu_affinity.switch_cpu(cpu_id);

        // Write events to this CPU's ring.
        for (const auto& msg : large_messages) {
            write_result = ebpf_perf_event_array_map_write(map_fd, msg.c_str(), msg.length());
            writes_attempted++;
            if (write_result != EBPF_SUCCESS) {
                failed_writes++;
            }
        }

        // Consume and verify lost events were detected.
        consume_result = perf_buffer__consume(pb);

        uint64_t received_so_far = helper.context.event_count;
        uint64_t lost_so_far = helper.context.lost_count;
        CAPTURE(cpu_id, consume_result, received_so_far, lost_so_far, writes_attempted, failed_writes);

        // Validate event counts match: exactly events_per_ring received and lost per CPU.
        REQUIRE(consume_result == static_cast<int>(events_per_ring));
        REQUIRE(failed_writes == lost_so_far);
        REQUIRE(writes_attempted == received_so_far + lost_so_far);
    }
}

// Test lost/dropped record handling through the synchronous perf buffer API.
// Tests three phases: normal operation, buffer overflow with lost events, and recovery.
TEST_CASE("perf_buffer_sync_callback_block", "[perf_buffer]")
{
    const size_t event_data_size = 504;

    // Load native perf_event_burst program.
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int map_fd = ebpf_fd_invalid;
    native_module_helper_t native_helper;

    native_helper.initialize("perf_event_burst", EBPF_EXECUTION_NATIVE);

    int result = program_load_helper(
        native_helper.get_file_name().c_str(), BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_NATIVE, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);
    REQUIRE(program_fd > 0);

    // RAII cleanup for program object. Declared before helper so bpf_object outlives the perf buffer
    // (perf_buffer__free uses map_fd for IOCTLs, and bpf_object__close closes the map fd).
    auto cleanup = std::unique_ptr<bpf_object, decltype(&bpf_object__close)>(object, bpf_object__close);

    struct bpf_map* burst_map = bpf_object__find_map_by_name(object, "burst_test_map");
    REQUIRE(burst_map != nullptr);
    map_fd = bpf_map__fd(burst_map);
    REQUIRE(map_fd > 0);

    perf_buffer_test_helper helper(false); // Don't keep records

    // Create synchronous perf buffer.
    auto pb = helper.create_perf_buffer(map_fd);
    REQUIRE(pb != nullptr);

    // Local tracking variables for consumer thread.
    std::atomic<bool> terminate_flag{false};
    std::atomic<uint64_t> total_polled_events{0};

    // Spawn consumer thread to poll perf buffer.
    std::thread consumer_thread([&]() {
        auto timeout_time = std::chrono::steady_clock::now() + 20s;
        while (!terminate_flag.load() && std::chrono::steady_clock::now() < timeout_time) {
            int poll_result = perf_buffer__poll(pb, 100);
            // Poll returns 0 on timeout or event count on data; exact value depends on timing.
            REQUIRE(poll_result >= 0);
            total_polled_events.fetch_add(poll_result);
        }
    });

    auto thread_cleanup = std::unique_ptr<void, std::function<void(void*)>>(reinterpret_cast<void*>(1), [&](void*) {
        terminate_flag.store(true);
        helper.unblock_callback();
        if (consumer_thread.joinable()) {
            consumer_thread.join();
        }
    });

    // Prepare data buffer for sending.
    std::vector<uint8_t> event_data(event_data_size);
    for (size_t i = 0; i < event_data_size; i++) {
        event_data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    struct phase_config_t
    {
        bool block_callback;
        uint32_t burst_count;
        uint32_t iterations;
        bool expect_overflow;
    };

    uint32_t num_cpus = static_cast<uint32_t>(libbpf_num_possible_cpus());
    // Execute test phases: normal operation, overflow with lost events, recovery.
    phase_config_t phases[] = {
        {false, 32, 1, false},      // First write events with simultaneous consumer.
        {true, 32, 1, false},       // Block in consumer callback, write enough to not overflow.
        {true, 33, num_cpus, true}, // Block consumer callback and write enough to guarantee overflow.
        {false, 32, 1, false},      // Ensure recovery after unblocking consumer.
    };

    for (const auto& phase : phases) {
        uint64_t events_start = helper.context.event_count.load();
        uint64_t lost_start = helper.context.lost_count.load();
        uint64_t polled_start = total_polled_events.load();

        if (phase.block_callback) {
            helper.block_callback();
        }

        uint32_t phase_written = 0;
        uint32_t phase_failed_writes = 0;
        for (uint32_t i = 0; i < phase.iterations; i++) {
            struct
            {
                EBPF_CONTEXT_HEADER;
                sample_program_context_t context;
            } ctx_header = {0};

            ctx_header.context.uint32_data = phase.burst_count;
            ctx_header.context.data_start = event_data.data();
            ctx_header.context.data_end = event_data.data() + event_data.size();

            bpf_test_run_opts opts = {0};
            opts.sz = sizeof(opts);
            opts.ctx_in = &ctx_header.context;
            opts.ctx_size_in = sizeof(ctx_header);
            opts.ctx_out = &ctx_header;
            opts.ctx_size_out = sizeof(ctx_header);
            opts.data_in = event_data.data();
            opts.data_size_in = static_cast<uint32_t>(event_data.size());
            opts.data_out = event_data.data();
            opts.data_size_out = static_cast<uint32_t>(event_data.size());

            int invoke_result = bpf_prog_test_run_opts(program_fd, &opts);
            int32_t burst_result = static_cast<int32_t>(opts.retval);
            REQUIRE(invoke_result == 0);
            // burst_result is the BPF program's count of failed writes (0 if no overflow).
            REQUIRE(burst_result >= 0);
            phase_failed_writes += burst_result;
            phase_written += phase.burst_count;
        }

        if (phase.expect_overflow) {
            REQUIRE(phase_failed_writes > 0);
        } else {
            REQUIRE(phase_failed_writes == 0);
        }

        if (phase.block_callback) { // Unblock consumer to flush all records.
            helper.unblock_callback();
        }
        // Wait for all callbacks to fire AND for poll to return (so total_polled_events is updated).
        // The callbacks fire inside _process_ring_records (within poll), but total_polled_events
        // is only updated after poll returns. We need to wait for both.
        for (int i = 0; i < 5; i++) {
            bool callbacks_done = (helper.context.event_count.load() + helper.context.lost_count.load()) >=
                                  (events_start + lost_start + phase_written);
            bool polled_done =
                (total_polled_events.load() - polled_start) >= (helper.context.event_count.load() - events_start);
            if (callbacks_done && polled_done) {
                break;
            }
            std::this_thread::sleep_for(1s);
        }

        uint64_t phase_events = helper.context.event_count.load() - events_start;
        uint64_t phase_lost = helper.context.lost_count.load() - lost_start;
        uint64_t phase_polled = total_polled_events.load() - polled_start;
        CAPTURE(phase_written, phase_failed_writes, phase_events, phase_lost, phase_polled);
        // Validate kernel and usermode results match.
        REQUIRE(phase_failed_writes == phase_lost);
        REQUIRE(phase_events + phase_lost == phase_written);
        REQUIRE(phase_polled == phase_events);
    }
}

// Test that BPF_F_INDEX_MASK (explicit CPU index in flags) works for perf_event_output.
// The BPF program targets a specific CPU via flags; the test validates that:
// 1. Writing to the current CPU (matching opts.cpu) succeeds and the event is consumable.
// 2. Writing to a different CPU (mismatching opts.cpu) fails in the BPF program.
TEST_CASE("perf_buffer_cpu_target", "[perf_buffer]")
{
    // Load native perf_event_cpu_target program.
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    native_module_helper_t native_helper;

    native_helper.initialize("perf_event_cpu_target", EBPF_EXECUTION_NATIVE);

    int result = program_load_helper(
        native_helper.get_file_name().c_str(), BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_NATIVE, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);
    REQUIRE(program_fd > 0);

    // RAII cleanup for program object. Declared before helper so bpf_object outlives the perf buffer.
    auto cleanup = std::unique_ptr<bpf_object, decltype(&bpf_object__close)>(object, bpf_object__close);

    struct bpf_map* target_map = bpf_object__find_map_by_name(object, "cpu_target_map");
    REQUIRE(target_map != nullptr);
    int map_fd = bpf_map__fd(target_map);
    REQUIRE(map_fd > 0);

    perf_buffer_test_helper helper;

    // Create synchronous perf buffer.
    auto pb = helper.create_perf_buffer(map_fd);
    REQUIRE(pb != nullptr);

    // Prepare event data buffer (mutable for data_out).
    const size_t event_data_size = 20;
    std::vector<uint8_t> event_data(event_data_size);
    for (size_t i = 0; i < event_data_size; i++) {
        event_data[i] = static_cast<uint8_t>(i & 0xFF);
    }
    std::string expected_payload(event_data.begin(), event_data.end());

    // Helper to invoke the BPF program targeting a specific CPU index.
    // run_cpu: CPU to run the program on (opts.cpu).
    // target_cpu_index: CPU index to pass to the BPF program as the perf_event_output flag.
    auto invoke_program = [&](uint32_t run_cpu, uint32_t target_cpu_index) -> int32_t {
        struct
        {
            EBPF_CONTEXT_HEADER;
            sample_program_context_t context;
        } ctx_header = {0};

        ctx_header.context.uint32_data = target_cpu_index;
        ctx_header.context.data_start = event_data.data();
        ctx_header.context.data_end = event_data.data() + event_data.size();

        bpf_test_run_opts opts = {0};
        opts.sz = sizeof(opts);
        opts.ctx_in = &ctx_header.context;
        opts.ctx_size_in = sizeof(ctx_header);
        opts.ctx_out = &ctx_header;
        opts.ctx_size_out = sizeof(ctx_header);
        opts.data_in = event_data.data();
        opts.data_size_in = static_cast<uint32_t>(event_data.size());
        opts.data_out = event_data.data();
        opts.data_size_out = static_cast<uint32_t>(event_data.size());
        opts.cpu = run_cpu;

        int invoke_result = bpf_prog_test_run_opts(program_fd, &opts);
        REQUIRE(invoke_result == 0);
        return static_cast<int32_t>(opts.retval);
    };

    uint32_t target_cpu = 0;

    // Test 1: Write to current CPU (matching) should succeed.
    {
        int32_t bpf_result = invoke_program(target_cpu, target_cpu);
        REQUIRE(bpf_result == 0);

        // Consume the event from the target CPU's buffer.
        int consume_result = perf_buffer__consume_buffer(pb, target_cpu);
        REQUIRE(consume_result == 1);

        // Verify event data.
        REQUIRE(helper.context.event_count == 1);
        helper.validate_data({expected_payload});
    }

    // Test 2: Write to a different CPU (mismatching) should fail.
    {
        int cpu_count = libbpf_num_possible_cpus();
        REQUIRE(cpu_count > 1);

        // Target CPU 1, but run on CPU 0 — the write should fail.
        uint32_t wrong_cpu = 1;
        int32_t bpf_result = invoke_program(target_cpu, wrong_cpu);
        REQUIRE(bpf_result != 0);

        // No new events should have been written to either buffer.
        REQUIRE(perf_buffer__consume_buffer(pb, target_cpu) == 0);
        REQUIRE(perf_buffer__consume_buffer(pb, wrong_cpu) == 0);
    }
}

TEST_CASE("Test program order", "[native_tests]")
{
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    uint32_t program_count = 4;
    int result;

    REQUIRE(
        program_load_helper(
            "multiple_programs.sys", BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_NATIVE, &object, &program_fd) == 0);

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

// Test eBPF string and type conversion APIs.
TEST_CASE("ebpf_string_apis", "[ebpf_api]")
{
    // Test ebpf_free_string - can be called with NULL safely.
    ebpf_free_string(nullptr);

    // Test program type name lookup.
    ebpf_program_type_t sample_program_type = EBPF_PROGRAM_TYPE_BIND_GUID;
    const char* type_name = ebpf_get_program_type_name(&sample_program_type);
    REQUIRE(type_name != nullptr);
    REQUIRE(std::string(type_name) == "bind"); // Verify actual content

    // Test attach type name lookup.
    ebpf_attach_type_t bind_attach_type = EBPF_ATTACH_TYPE_BIND_GUID;
    const char* attach_name = ebpf_get_attach_type_name(&bind_attach_type);
    REQUIRE(attach_name != nullptr);
    REQUIRE(std::string(attach_name) == "bind"); // Verify actual content

    // Test with invalid/unknown program type to verify graceful handling.
    ebpf_program_type_t invalid_type = {0};
    const char* invalid_name = ebpf_get_program_type_name(&invalid_type);
    // Should either return nullptr or empty string for unknown types.
    REQUIRE((invalid_name == nullptr || strlen(invalid_name) == 0));
}

// Test eBPF program and attach type conversion APIs.
TEST_CASE("ebpf_type_conversion_apis", "[ebpf_api]")
{
    // Test BPF to eBPF program type conversion.
    const ebpf_program_type_t* ebpf_type = ebpf_get_ebpf_program_type(BPF_PROG_TYPE_SAMPLE);
    REQUIRE(ebpf_type != nullptr);

    // Test reverse conversion.
    bpf_prog_type_t bpf_type = ebpf_get_bpf_program_type(ebpf_type);
    REQUIRE(bpf_type == BPF_PROG_TYPE_SAMPLE);

    // Test BPF to eBPF attach type conversion.
    ebpf_attach_type_t ebpf_attach_type;
    ebpf_result_t result = ebpf_get_ebpf_attach_type(BPF_ATTACH_TYPE_BIND, &ebpf_attach_type);
    REQUIRE(result == EBPF_SUCCESS);

    // Test reverse conversion.
    bpf_attach_type_t bpf_attach_type = ebpf_get_bpf_attach_type(&ebpf_attach_type);
    REQUIRE(bpf_attach_type == BPF_ATTACH_TYPE_BIND);

    // Test program type lookup by name.
    ebpf_program_type_t program_type;
    ebpf_attach_type_t expected_attach_type;
    result = ebpf_get_program_type_by_name("bind", &program_type, &expected_attach_type);
    REQUIRE(result == EBPF_SUCCESS);

    // Verify the lookup worked by converting back to name.
    const char* retrieved_name = ebpf_get_program_type_name(&program_type);
    REQUIRE(retrieved_name != nullptr);
    REQUIRE(std::string(retrieved_name) == "bind");
}

// Test path canonicalization API.
TEST_CASE("ebpf_canonicalize_pin_path", "[ebpf_api]")
{
    char output[MAX_PATH];

    // Test with a simple path.
    ebpf_result_t result = ebpf_canonicalize_pin_path(output, sizeof(output), "/some/test/path");
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(std::string(output) == "BPF:\\some\\test\\path");

    // Test with empty path.
    result = ebpf_canonicalize_pin_path(output, sizeof(output), "");
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(std::string(output) == "BPF:\\");

    // Negative test: buffer too small.
    char small_output[5];
    result = ebpf_canonicalize_pin_path(small_output, sizeof(small_output), "/some/very/long/path/that/wont/fit");
    REQUIRE(result != EBPF_SUCCESS);
}

// Test enumerate programs API.
TEST_CASE("ebpf_enumerate_programs", "[ebpf_api]")
{
    // Test with a known test file path - using sample programs from the project.
    auto test_cases = std::map<std::string, std::function<void(ebpf_api_program_info_t*)>>{
        {"test_sample_ebpf.o",
         [](ebpf_api_program_info_t* info) {
             REQUIRE(std::string(info->section_name) == "sample_ext");
             REQUIRE(std::string(info->program_name) == "test_program_entry");
             REQUIRE(info->program_type == EBPF_PROGRAM_TYPE_SAMPLE);
             REQUIRE(info->expected_attach_type == EBPF_ATTACH_TYPE_SAMPLE);
         }},
        {"bindmonitor.o", [](ebpf_api_program_info_t* info) {
             REQUIRE(std::string(info->section_name) == "bind");
             REQUIRE(std::string(info->program_name) == "BindMonitor");
             REQUIRE(info->program_type == EBPF_PROGRAM_TYPE_BIND);
             REQUIRE(info->expected_attach_type == EBPF_ATTACH_TYPE_BIND);
         }}};

    for (const auto& [file, validate] : test_cases) {
        ebpf_api_program_info_t* program_infos = nullptr;
        const char* error_message = nullptr;

        // Try to enumerate programs from test file.
        ebpf_result_t result = ebpf_enumerate_programs(file.c_str(), false, &program_infos, &error_message);

        if (result == EBPF_SUCCESS && program_infos != nullptr) {
            // Verify we got some program info.
            REQUIRE(program_infos->section_name != nullptr);
            REQUIRE(strlen(program_infos->section_name) > 0);
            validate(program_infos);

            // Clean up.
            ebpf_free_programs(program_infos);
        }

        // Clean up error message if any.
        ebpf_free_string(error_message);
    }

    // Test with non-existent file - should fail gracefully.
    ebpf_api_program_info_t* program_infos = nullptr;
    const char* error_message = nullptr;
    ebpf_result_t result = ebpf_enumerate_programs("non_existent_file.o", false, &program_infos, &error_message);
    REQUIRE(result != EBPF_SUCCESS);
    // Should provide error message when operation fails.
    REQUIRE(error_message != nullptr);

    // Clean up error message.
    ebpf_free_string(error_message);

    // Negative test: null file path.
    error_message = nullptr;
    program_infos = nullptr;

    // Can't test with null parameter directly as this violates the static analysis checks and causes crash at runtime.
}

// Test eBPF verification APIs.
TEST_CASE("ebpf_verification_apis", "[ebpf_api]")
{
    // Test file verification APIs with known test files.
    const char* test_files[] = {"test_sample_ebpf.o", "bindmonitor.o"};

    for (const char* file : test_files) {
        const char* report = nullptr;
        const char* error_message = nullptr;
        ebpf_api_verifier_stats_t stats = {};

        // Test program verification from file.
        uint32_t result = ebpf_api_elf_verify_program_from_file(
            file,
            nullptr, // section_name - use first section.
            nullptr, // program_name - use first program.
            nullptr, // program_type - derive from section.
            EBPF_VERIFICATION_VERBOSITY_NORMAL,
            &report,
            &error_message,
            &stats);

        // Result should be 0 (success).
        REQUIRE(result == 0);

        // Verify that stats are populated for successful verification.
        REQUIRE(report != nullptr); // Should generate a report

        // Clean up strings.
        ebpf_free_string(report);
        ebpf_free_string(error_message);
    }

    // Negative test: invalid ELF data.
    {
        const char* report = nullptr;
        const char* error_message = nullptr;
        ebpf_api_verifier_stats_t stats = {};
        const char* invalid_data = "this is not valid ELF data";

        uint32_t result = ebpf_api_elf_verify_program_from_memory(
            invalid_data,
            strlen(invalid_data),
            nullptr,
            nullptr,
            nullptr,
            EBPF_VERIFICATION_VERBOSITY_NORMAL,
            &report,
            &error_message,
            &stats);

        // Should fail validation.
        REQUIRE(result != 0);
        // Should provide error details.
        REQUIRE(error_message != nullptr);

        ebpf_free_string(report);
        ebpf_free_string(error_message);
    }

    // Test disassembly APIs.
    for (const char* file : test_files) {
        const char* disassembly = nullptr;
        const char* error_message = nullptr;

        // Test program disassembly from file.
        uint32_t result = ebpf_api_elf_disassemble_program(
            file,
            nullptr, // section_name - use first section.
            nullptr, // program_name - use first program.
            &disassembly,
            &error_message);

        if (result == 0 && disassembly != nullptr) {
            // Verify we got some disassembly output.
            REQUIRE(strlen(disassembly) > 0);
        }

        // Clean up strings.
        ebpf_free_string(disassembly);
        ebpf_free_string(error_message);
    }
}

// Test eBPF object management APIs.
TEST_CASE("ebpf_object_apis", "[ebpf_api]")
{
    // Create a simple map object.
    fd_t map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "test_map_pin", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(map_fd > 0);

    // Pin the map object.
    const char* pin_path = "BPF:\\test_map_pin";
    int pin_result = bpf_obj_pin(map_fd, pin_path);
    REQUIRE(pin_result == 0);

    // Call ebpf_api_get_pinned_map_info to get pinned map info.
    uint16_t map_count = 0;
    ebpf_map_info_t* map_info = nullptr;
    ebpf_result_t result = ebpf_api_get_pinned_map_info(&map_count, &map_info);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(map_count == 1);
    REQUIRE(map_info != nullptr);

    // Validate ALL fields of the returned map info.
    REQUIRE(map_info[0].definition.type == BPF_MAP_TYPE_ARRAY);
    REQUIRE(std::string(map_info[0].pin_path) == "BPF:\\test_map_pin");
    REQUIRE(map_info[0].definition.key_size == sizeof(uint32_t));
    REQUIRE(map_info[0].definition.value_size == sizeof(uint32_t));
    REQUIRE(map_info[0].definition.max_entries == 1);
    REQUIRE(map_info[0].definition.inner_map_id == 0);

    // Clean up pinned map info returned by the API.
    ebpf_api_map_info_free(map_count, map_info);

    // Negative test: null count parameter.
    // Test can not be performed as it violates static analysis checks and causes an assert at runtime.

    // Negative test: null info parameter.
    // Test can not be performed as it violates static analysis checks and causes an assert at runtime.

    // Unpin the map object.
    result = ebpf_object_unpin(pin_path);
    REQUIRE(result == EBPF_SUCCESS);

    // Verify that unpinning the object a second time fails.
    result = ebpf_object_unpin(pin_path);
    REQUIRE(result != EBPF_SUCCESS);

    // Verify that the map can no longer be found via ebpf_api_get_pinned_map_info.
    result = ebpf_api_get_pinned_map_info(&map_count, &map_info);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(map_count == 0);
    REQUIRE(map_info == nullptr);

    // Verify free is a no-op for empty results.
    ebpf_api_map_info_free(map_count, map_info);

    // Close the map fd.
    _close(map_fd);
}

// Test eBPF pinned object path APIs.
TEST_CASE("ebpf_pinned_path_apis", "[ebpf_api]")
{
    char next_path[EBPF_MAX_PIN_PATH_LENGTH];
    ebpf_object_type_t object_type = EBPF_OBJECT_UNKNOWN;

    // 1) Create and pin a map.
    const char* pin_path = "BPF:\\test_get_next_pinned_object_path";
    fd_t map_fd = bpf_map_create(
        BPF_MAP_TYPE_ARRAY, "test_get_next_pinned_object_path", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(map_fd > 0);

    int pin_result = bpf_obj_pin(map_fd, pin_path);
    REQUIRE(pin_result == 0);

    // 2) Verify the map can be found via ebpf_get_next_pinned_object_path.
    ebpf_result_t result = ebpf_get_next_pinned_object_path("", next_path, sizeof(next_path), &object_type);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(object_type == EBPF_OBJECT_MAP);
    // Validate the full path structure.
    REQUIRE(strstr(next_path, "test_get_next_pinned_object_path") != nullptr);
    // Verify it starts with expected prefix.
    REQUIRE(strstr(next_path, "BPF:") == next_path);

    // 3) Test iteration - should be no more objects after this one.
    char second_path[EBPF_MAX_PIN_PATH_LENGTH];
    result = ebpf_get_next_pinned_object_path(next_path, second_path, sizeof(second_path), &object_type);
    REQUIRE(result == EBPF_NO_MORE_KEYS);

    // Negative test: null output buffer.
    // This test can not be performed as it violates static analysis checks and causes an assert at runtime.

    // Negative test: zero size buffer.
    result = ebpf_get_next_pinned_object_path("", next_path, 0, &object_type);
    REQUIRE(result != EBPF_SUCCESS);

    // 4) Unpin and free the map.
    ebpf_result_t unpin_result = ebpf_object_unpin(pin_path);
    REQUIRE(unpin_result == EBPF_SUCCESS);

    _close(map_fd);
}

/**
 * @brief Test that user mode reads (via bpf_map_lookup_elem) do not affect LRU state,
 * while kernel mode accesses (from eBPF programs) do affect LRU eviction order.
 * This ensures diagnostic tools can enumerate LRU maps without polluting the cache.
 *
 * Both the test thread and bpf program are pinned to cpu zero for a deterministic test.
 *
 * Test steps:
 * 1) Fill LRU map with 100 entries (keys 0-99).
 * 2) Access keys 0-79 from kernel mode to update their timestamps.
 * 3) Access keys 80-99 from user mode (bpf_map_lookup_elem) - these should be found but should NOT affect LRU state.
 * 4) Add 20 new entries (keys 100-119).
 * 5) Scan keys 0-119 and validate only the user-mode accessed keys were evicted (80-99).
 *
 */
TEST_CASE("lru_map_user_vs_kernel_access", "[lru]")
{
    const uint32_t max_entries = 100;     // Map with 100 entries.
    const uint32_t kernel_mode_keys = 80; // Keys accessed from kernel mode (0-79).
    const uint32_t user_mode_keys = 20;   // Keys accessed from user mode (80-99).
    const uint32_t new_keys = 20;         // Force 20 evictions.

    const uint32_t first_kernel_mode_key = 0;                                      // 0
    const uint32_t first_user_mode_key = first_kernel_mode_key + kernel_mode_keys; // 80
    const uint32_t first_new_key = first_user_mode_key + user_mode_keys;           // 100

    // Load eBPF program that performs kernel-mode lookups.
    struct bpf_object* object = nullptr;
    fd_t program_fd = ebpf_fd_invalid;
    fd_t map_fd = ebpf_fd_invalid;
    native_module_helper_t _native_helper;

    HANDLE thread_handle{GetCurrentThread()};
    // Pin test to cpu zero for deterministic test.
    DWORD_PTR original_mask = SetThreadAffinityMask(thread_handle, (1ULL << 0));
    REQUIRE(original_mask != 0);
    // Setup cleanup guard to ensure resources are freed on any exit path.
    auto cleanup = std::unique_ptr<void, std::function<void(void*)>>(
        reinterpret_cast<void*>(1), // Dummy pointer, we only care about the deleter.
        [&](void*) {
            if (object != nullptr) {
                bpf_object__close(object);
            }
            SetThreadAffinityMask(thread_handle, original_mask); // Restore cpu affinity.
        });

    _native_helper.initialize("lru_map_test", EBPF_EXECUTION_NATIVE);
    REQUIRE(
        program_load_helper(
            _native_helper.get_file_name().c_str(), BPF_PROG_TYPE_BIND, EBPF_EXECUTION_NATIVE, &object, &program_fd) ==
        0);

    // Get the LRU map from the loaded program.
    struct bpf_map* lru_map = bpf_object__find_map_by_name(object, "lru_map");
    REQUIRE(lru_map != nullptr);
    map_fd = bpf_map__fd(lru_map);
    REQUIRE(map_fd > 0);

    // Fill map completely (keys 0-99).
    for (uint32_t i = 0; i < max_entries; i++) {
        uint32_t value = 1000 + i;
        REQUIRE(bpf_map_update_elem(map_fd, &i, &value, BPF_ANY) == 0);
    }

    // Now do kernel-mode lookup of keys 0-79.
    // These lookups should affect LRU state (add to hot list with new generation).
    struct
    {
        EBPF_CONTEXT_HEADER;
        sample_program_context_t context;
    } ctx_header = {0};
    sample_program_context_t* ctx = &ctx_header.context;
    ctx->uint32_data = first_kernel_mode_key;      // Start key: 0.
    ctx->uint16_data = (uint16_t)kernel_mode_keys; // Number of keys: 80.

    bpf_test_run_opts test_run_opts = {0};
    test_run_opts.ctx_in = ctx;
    test_run_opts.ctx_size_in = sizeof(*ctx);
    test_run_opts.ctx_out = ctx;
    test_run_opts.ctx_size_out = sizeof(*ctx);
    test_run_opts.repeat = 1;
    test_run_opts.cpu = 0; // Force execution on CPU 0.

    int result = bpf_prog_test_run_opts(program_fd, &test_run_opts);
    REQUIRE(result == 0);
    CHECK((int32_t)test_run_opts.retval == (int32_t)kernel_mode_keys);

    // User-mode lookup of keys 80-99.
    // These lookups should NOT affect LRU state.
    for (uint32_t i = first_user_mode_key; i < first_user_mode_key + user_mode_keys; i++) {
        uint32_t value = 0;
        CAPTURE(i);
        REQUIRE(bpf_map_lookup_elem(map_fd, &i, &value) == 0);
        REQUIRE(value == (1000 + i));
    }

    // Insert new keys, forcing evictions.
    for (uint32_t i = first_new_key; i < first_new_key + new_keys; i++) {
        uint32_t value = 1000 + i;
        CAPTURE(i);
        REQUIRE(bpf_map_update_elem(map_fd, &i, &value, BPF_ANY) == 0);
    }

    uint32_t kernel_mode_keys_evicted = 0;
    for (uint32_t i = first_kernel_mode_key; i < first_kernel_mode_key + kernel_mode_keys; i++) {
        uint32_t value = 0;
        result = bpf_map_lookup_elem(map_fd, &i, &value);
        CAPTURE(i);
        CHECK(result == 0);
        if (result != 0) {
            REQUIRE(result == -ENOENT);
            kernel_mode_keys_evicted++;
        }
    }

    uint32_t user_mode_keys_evicted = 0;
    for (uint32_t i = first_user_mode_key; i < first_user_mode_key + user_mode_keys; i++) {
        uint32_t value = 0;
        result = bpf_map_lookup_elem(map_fd, &i, &value);
        CAPTURE(i);
        CHECK(result != 0);
        if (result != 0) {
            REQUIRE(result == -ENOENT);
            user_mode_keys_evicted++;
        }
    }

    uint32_t new_keys_found = 0;
    for (uint32_t i = first_new_key; i < first_new_key + new_keys; i++) {
        uint32_t value = 0;
        result = bpf_map_lookup_elem(map_fd, &i, &value);
        CAPTURE(i);
        CHECK(result == 0);
        if (result == 0) {
            new_keys_found++;
        } else {
            REQUIRE(result == -ENOENT);
        }
    }

    CAPTURE(user_mode_keys_evicted, kernel_mode_keys_evicted, new_keys_found);
    REQUIRE(user_mode_keys_evicted == user_mode_keys);
    REQUIRE(kernel_mode_keys_evicted == 0);
    REQUIRE(new_keys_found == new_keys);

    // Cleanup handled by scope guard.
}

// Test eBPF program synchronization API.
TEST_CASE("ebpf_program_synchronize", "[ebpf_api]")
{
    // Test program synchronization multiple times to ensure it's idempotent.
    for (int i = 0; i < 3; i++) {
        ebpf_result_t result = ebpf_program_synchronize();
        REQUIRE(result == EBPF_SUCCESS);
    }
}

// Test eBPF object execution type APIs.
TEST_CASE("ebpf_object_execution_type_apis", "[ebpf_api]")
{
    // Load a test object to test execution type APIs.
    struct bpf_object* object = bpf_object__open("test_sample_ebpf.o");
    if (object != nullptr) {
        // Test getting the default execution type - be flexible about default.
        ebpf_execution_type_t exec_type = ebpf_object_get_execution_type(object);
        REQUIRE(
            (exec_type == EBPF_EXECUTION_ANY || exec_type == EBPF_EXECUTION_JIT ||
             exec_type == EBPF_EXECUTION_INTERPRET || exec_type == EBPF_EXECUTION_NATIVE));
        ebpf_execution_type_t original_type = exec_type;

        // Test setting an invalid execution type.
        ebpf_execution_type_t invalid_execution_type = static_cast<ebpf_execution_type_t>(0x7fffffff);
        ebpf_result_t result = ebpf_object_set_execution_type(object, invalid_execution_type);
        REQUIRE(result == EBPF_INVALID_ARGUMENT);
        REQUIRE(ebpf_object_get_execution_type(object) == original_type);

        // Test setting execution type to INTERPRET.
        result = ebpf_object_set_execution_type(object, EBPF_EXECUTION_INTERPRET);
        if (result == EBPF_SUCCESS) {
            // Verify the execution type was set.
            exec_type = ebpf_object_get_execution_type(object);
            REQUIRE(exec_type == EBPF_EXECUTION_INTERPRET);
        } else {
            // If setting fails, verify the original value is unchanged.
            ebpf_execution_type_t new_exec_type = ebpf_object_get_execution_type(object);
            REQUIRE(new_exec_type == original_type);
        }

        // Test setting to JIT.
        result = ebpf_object_set_execution_type(object, EBPF_EXECUTION_JIT);
        if (result == EBPF_SUCCESS) {
            exec_type = ebpf_object_get_execution_type(object);
            REQUIRE(exec_type == EBPF_EXECUTION_JIT);
        }

        bpf_object__close(object);
    }
}

// Test eBPF perf event array API.
TEST_CASE("ebpf_perf_event_array_api", "[ebpf_api]")
{
    // Create a perf event array map for testing.
    fd_t map_fd = bpf_map_create(BPF_MAP_TYPE_PERF_EVENT_ARRAY, "test_perf", 0, 0, 4, nullptr);
    if (map_fd > 0) {
        // Test writing to perf event array.
        const char test_data[] = "test perf event data";
        ebpf_result_t result = ebpf_perf_event_array_map_write(map_fd, test_data, sizeof(test_data));

        REQUIRE(result == EBPF_SUCCESS);

        // Negative test: invalid file descriptor.
        result = ebpf_perf_event_array_map_write(-1, test_data, sizeof(test_data));
        REQUIRE(result != EBPF_SUCCESS);

        // Negative test: null data.
        // Not tested: passing nullptr violates SAL annotations.

        // Negative test: zero size.
        result = ebpf_perf_event_array_map_write(map_fd, test_data, 0);
        REQUIRE(result != EBPF_SUCCESS);

        (void)ebpf_close_fd(map_fd);
    }
}

// Test eBPF object info API.
TEST_CASE("ebpf_object_info_api", "[ebpf_api]")
{
    _disable_crt_report_hook disable_hook;

    // Create a simple map to test object info API.
    fd_t map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "test_map", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
    REQUIRE(map_fd > 0);

    struct bpf_map_info info = {0};
    uint32_t info_size = sizeof(info);
    ebpf_object_type_t object_type;

    ebpf_result_t result = ebpf_object_get_info_by_fd(map_fd, &info, &info_size, &object_type);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(object_type == EBPF_OBJECT_MAP);
    REQUIRE(info_size > 0);
    REQUIRE(info.type == BPF_MAP_TYPE_ARRAY);
    REQUIRE(info.key_size == sizeof(uint32_t));
    REQUIRE(info.value_size == sizeof(uint32_t));
    REQUIRE(info.max_entries == 1);
    REQUIRE(info.id != 0);
    REQUIRE(std::string(info.name) == "test_map");

    (void)ebpf_close_fd(map_fd);

    // Test with invalid fd.
    result = ebpf_object_get_info_by_fd(-1, nullptr, &info_size, &object_type);
    REQUIRE(result != EBPF_SUCCESS);
}

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
// Test eBPF program attach APIs with graceful error handling.
TEST_CASE("ebpf_program_attach_apis_basic", "[ebpf_api]")
{
    _disable_crt_report_hook disable_hook;

    // Load test_sample_ebpf.o to get a valid program fd.
    bpf_object* object = bpf_object__open_file("test_sample_ebpf.o", nullptr);
    REQUIRE(object != nullptr);

    REQUIRE(bpf_object__load(object) == 0);

    // Load the first program in the object.
    bpf_program* program = bpf_object__next_program(object, nullptr);
    REQUIRE(program != nullptr);

    int program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    // Test attach with a valid fd - should succeed.
    struct bpf_link* link = nullptr;
    GUID sample_attach_type = EBPF_ATTACH_TYPE_SAMPLE_GUID;
    ebpf_result_t result = ebpf_program_attach_by_fd(program_fd, &sample_attach_type, nullptr, 0, &link);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(link != nullptr);

    ebpf_link_close(link);

    bpf_object__close(object);

    // Test with invalid fd.
    result = ebpf_program_attach_by_fd(-1, &sample_attach_type, nullptr, 0, &link);
    REQUIRE(result != EBPF_SUCCESS);
}
#endif

// Test eBPF native object loading API.
TEST_CASE("ebpf_object_load_native_api", "[ebpf_api]")
{
    // Test loading native object with invalid file.
    size_t map_count = 1;
    size_t program_count = 1;
    std::vector<fd_t> map_fds(1);
    std::vector<fd_t> program_fds(1);

    ebpf_result_t result = ebpf_object_load_native_by_fds(
        "test_sample_ebpf.sys", &map_count, map_fds.data(), &program_count, program_fds.data());

    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(map_count == 1);
    REQUIRE(program_count == 1);
    REQUIRE(map_fds[0] > 0);
    REQUIRE(program_fds[0] > 0);
    _close(map_fds[0]);
    _close(program_fds[0]);
}

// Test eBPF program info from verifier API.
TEST_CASE("ebpf_program_info_from_verifier_api", "[ebpf_api]")
{
    const ebpf_program_info_t* program_info = nullptr;
    const char* error_message = nullptr;
    const char* report = nullptr;

    uint32_t verify_result = ebpf_api_elf_verify_program_from_file(
        "test_sample_ebpf.o",
        nullptr, // section_name - use first section.
        nullptr, // program_name - use first program.
        nullptr, // program_type - derive from section.
        EBPF_VERIFICATION_VERBOSITY_NORMAL,
        &report,        // report
        &error_message, // error_message
        nullptr         // stats
    );

    REQUIRE(verify_result == 0);
    REQUIRE(report != nullptr);
    ebpf_free_string(report);
    REQUIRE(error_message == nullptr);

    ebpf_result_t result = ebpf_get_program_info_from_verifier(&program_info);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(program_info != nullptr);
}

// Test eBPF memory-based verification APIs.
TEST_CASE("ebpf_verification_memory_apis", "[ebpf_api]")
{
    // Test memory-based verification with minimal data.
    const char* test_data = "minimal_test_data";
    const char* report = nullptr;
    const char* error_message = nullptr;
    ebpf_api_verifier_stats_t stats = {};

    // Test program verification from memory with invalid data.
    uint32_t result = ebpf_api_elf_verify_program_from_memory(
        test_data,
        strlen(test_data),
        nullptr, // section_name
        nullptr, // program_name
        nullptr, // program_type
        EBPF_VERIFICATION_VERBOSITY_NORMAL,
        &report,
        &error_message,
        &stats);

    // Should fail for invalid ELF data but handle gracefully.
    REQUIRE(result != 0); // Not successful verification.

    // Clean up strings.
    ebpf_free_string(report);
    ebpf_free_string(error_message);

    // Test with null data - should fail gracefully.
    result = ebpf_api_elf_verify_program_from_memory(
        nullptr, 0, nullptr, nullptr, nullptr, EBPF_VERIFICATION_VERBOSITY_NORMAL, &report, &error_message, &stats);
    REQUIRE(result != 0);

    // Clean up strings.
    ebpf_free_string(report);
    ebpf_free_string(error_message);
}