// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief Common test functions used by end to end and component tests.
 */

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "ebpf_result.h"

#include <windows.h>
#include <future>

#define RING_BUFFER_TEST_EVENT_COUNT 10

typedef struct _close_bpf_object
{
    void
    operator()(_In_opt_ _Post_invalid_ bpf_object* object)
    {
        if (object != nullptr) {
            bpf_object__close(object);
        }
    }
} close_bpf_object_t;
typedef std::unique_ptr<bpf_object, close_bpf_object_t> bpf_object_ptr;

void
ebpf_test_pinned_map_enum();
void
verify_utility_helper_results(_In_ const bpf_object* object, bool helper_override);

typedef struct _ring_buffer_test_event_context
{
    _ring_buffer_test_event_context();
    ~_ring_buffer_test_event_context();
    void
    unsubscribe();
    std::promise<void> ring_buffer_event_promise;
    struct ring_buffer* ring_buffer;
    std::vector<std::vector<char>>* records;
    bool canceled;
    int matched_entry_count;
    int test_event_count;
} ring_buffer_test_event_context_t;

int
ring_buffer_test_event_handler(_Inout_ void* ctx, _In_opt_ const void* data, size_t size);

void
ring_buffer_api_test_helper(
    fd_t ring_buffer_map, std::vector<std::vector<char>>& expected_records, std::function<void(int)> generate_event);
