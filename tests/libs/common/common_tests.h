// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Common test functions used by end to end and component tests.

#pragma once
#include <future>
#include <windows.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "ebpf_result.h"

void
ebpf_test_pinned_map_enum();

#define RING_BUFFER_TEST_EVENT_COUNT 10

void
verify_utility_helper_results(_In_ const bpf_object* object);

int
ring_buffer_test_event_handler(_In_ void* ctx, _In_opt_ void* data, size_t size);

void
ring_buffer_api_test_helper(
    fd_t ring_buffer_map, std::vector<std::vector<char>>& expected_records, std::function<void(int)> generate_event);