// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Common test functions used by end to end and component tests.
 */

#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "platform.h"
#include "sample_test_common.h"

#include <chrono>
#include <future>
#include <map>
using namespace std::chrono_literals;

bool use_ebpf_store = true;

void
ebpf_test_pinned_map_enum()
{
    int error;
    uint32_t return_value;
    ebpf_result_t result;
    const int pinned_map_count = 10;
    std::string pin_path_prefix = "\\ebpf\\map\\";
    uint16_t map_count = 0;
    ebpf_map_info_t* map_info = nullptr;
    std::map<std::string, std::string> results;

    fd_t map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint64_t), 1024, nullptr);
    REQUIRE(map_fd >= 0);

    if (map_fd < 0) {
        goto Exit;
    }

    for (int i = 0; i < pinned_map_count; i++) {
        std::string pin_path = pin_path_prefix + std::to_string(i);
        error = bpf_obj_pin(map_fd, pin_path.c_str());
        REQUIRE(error == 0);
        if (error != 0) {
            goto Exit;
        }
    }

    REQUIRE((result = ebpf_api_get_pinned_map_info(&map_count, &map_info)) == EBPF_SUCCESS);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    REQUIRE(map_count == pinned_map_count);
    REQUIRE(map_info != nullptr);
    if (map_info == nullptr) {
        goto Exit;
    }

    _Analysis_assume_(pinned_map_count == map_count);
    for (int i = 0; i < pinned_map_count; i++) {
        bool matched = false;
        std::string pin_path = pin_path_prefix + std::to_string(i);
        REQUIRE((
            matched =
                (static_cast<uint16_t>(pin_path.size()) == strnlen_s(map_info[i].pin_path, EBPF_MAX_PIN_PATH_LENGTH))));
        std::string temp(map_info[i].pin_path);
        results[pin_path] = temp;

        // Unpin the object.
        REQUIRE((return_value = ebpf_object_unpin(pin_path.c_str())) == EBPF_SUCCESS);
    }

    REQUIRE(results.size() == pinned_map_count);
    for (int i = 0; i < pinned_map_count; i++) {
        std::string pin_path = pin_path_prefix + std::to_string(i);
        REQUIRE(results.find(pin_path) != results.end());
    }

Exit:
    Platform::_close(map_fd);
    ebpf_api_map_info_free(map_count, map_info);
    map_count = 0;
    map_info = nullptr;
}

void
verify_utility_helper_results(_In_ const bpf_object* object, bool helper_override)
{
    fd_t utility_map_fd = bpf_object__find_map_fd_by_name(object, "utility_map");
    ebpf_utility_helpers_data_t test_data[UTILITY_MAP_SIZE];
    for (uint32_t key = 0; key < UTILITY_MAP_SIZE; key++) {
        REQUIRE(bpf_map_lookup_elem(utility_map_fd, &key, (void*)&test_data[key]) == EBPF_SUCCESS);
    }

    REQUIRE(test_data[0].random != test_data[1].random);
    REQUIRE(test_data[0].timestamp < test_data[1].timestamp);
    REQUIRE(test_data[0].boot_timestamp < test_data[1].boot_timestamp);
    REQUIRE(
        (test_data[1].boot_timestamp - test_data[0].boot_timestamp) >=
        (test_data[1].timestamp - test_data[0].timestamp));

    if (helper_override) {
        REQUIRE(test_data[0].pid_tgid == SAMPLE_EXT_PID_TGID);
        REQUIRE(test_data[1].pid_tgid == SAMPLE_EXT_PID_TGID);
    } else {
        REQUIRE(test_data[0].pid_tgid != SAMPLE_EXT_PID_TGID);
        REQUIRE(test_data[1].pid_tgid != SAMPLE_EXT_PID_TGID);
    }
}

ring_buffer_test_event_context_t::_ring_buffer_test_event_context()
    : ring_buffer(nullptr), records(nullptr), canceled(false), matched_entry_count(0), test_event_count(0)
{}
ring_buffer_test_event_context_t::~_ring_buffer_test_event_context()
{
    if (ring_buffer != nullptr) {
        ring_buffer__free(ring_buffer);
    }
}
void
ring_buffer_test_event_context_t::unsubscribe()
{
    struct ring_buffer* temp = ring_buffer;
    ring_buffer = nullptr;
    // Unsubscribe.
    ring_buffer__free(temp);
}

int
ring_buffer_test_event_handler(_Inout_ void* ctx, _In_opt_ const void* data, size_t size)
{
    ring_buffer_test_event_context_t* event_context = reinterpret_cast<ring_buffer_test_event_context_t*>(ctx);

    if ((data == nullptr) || (size == 0)) {
        // eBPF ring buffer invokes callback with NULL data indicating that the subscription is canceled.
        // This is the last callback. Free the callback context.
        delete event_context;
        return 0;
    }

    if (event_context->canceled) {
        // Ignore the callback as the subscription is canceled.
        // Return error so that no further callback is made.
        return -1;
    }

    if (event_context->matched_entry_count == event_context->test_event_count) {
        // Required number of event notifications already received.
        return 0;
    }

    std::vector<char> event_record(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data) + size);
    // Check if indicated event record matches an entry in the context records.
    auto records = event_context->records;
    auto it = std::find(records->begin(), records->end(), event_record);
    if (it != records->end()) {
        event_context->matched_entry_count++;
    }
    if (event_context->matched_entry_count == event_context->test_event_count) {
        // If all the entries in the app ID list was found, fulfill the promise.
        event_context->ring_buffer_event_promise.set_value();
    }
    return 0;
}

void
ring_buffer_api_test_helper(
    fd_t ring_buffer_map, std::vector<std::vector<char>>& expected_records, std::function<void(int)> generate_event)
{
    // Ring buffer event callback context.
    std::unique_ptr<ring_buffer_test_event_context_t> context = std::make_unique<ring_buffer_test_event_context_t>();
    context->test_event_count = RING_BUFFER_TEST_EVENT_COUNT;

    context->records = &expected_records;

    // Generate events prior to subscribing for ring buffer events.
    for (int i = 0; i < RING_BUFFER_TEST_EVENT_COUNT / 2; i++) {
        generate_event(i);
    }

    // Get the std::future from the promise field in ring buffer event context, which should be in ready state
    // once notifications for all events are received.
    auto ring_buffer_event_callback = context->ring_buffer_event_promise.get_future();

    // Create a new ring buffer manager and subscribe to ring buffer events.
    // The notifications for the events that were generated before should occur after the subscribe call.
    context->ring_buffer = ring_buffer__new(
        ring_buffer_map, (ring_buffer_sample_fn)ring_buffer_test_event_handler, context.get(), nullptr);
    REQUIRE(context->ring_buffer != nullptr);

    // Generate more events, post-subscription.
    for (int i = RING_BUFFER_TEST_EVENT_COUNT / 2; i < RING_BUFFER_TEST_EVENT_COUNT; i++) {
        generate_event(i);
    }

    // Wait for event handler getting notifications for all RING_BUFFER_TEST_EVENT_COUNT events.
    REQUIRE(ring_buffer_event_callback.wait_for(1s) == std::future_status::ready);

    // Mark the event context as canceled, such that the event callback stops processing events.
    context->canceled = true;

    // Release the raw pointer such that the final callback frees the callback context.
    ring_buffer_test_event_context_t* raw_context = context.release();

    // Unsubscribe.
    raw_context->unsubscribe();
}