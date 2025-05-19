// Copyright (c) eBPF for Windows contributors
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
#include <crtdbg.h>
#include <future>
#include <set>

#define RING_BUFFER_TEST_EVENT_COUNT 10
#define PERF_BUFFER_TEST_EVENT_COUNT 10

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
ebpf_test_pinned_map_enum(bool verify_pin_path);
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
    const std::vector<std::vector<char>>* records;
    std::set<size_t> event_received;
    bool canceled;
    int matched_entry_count;
    int test_event_count;
} ring_buffer_test_event_context_t;

int
ring_buffer_test_event_handler(_Inout_ void* ctx, _In_opt_ const void* data, size_t size);

void
ring_buffer_api_test_helper(
    fd_t ring_buffer_map, std::vector<std::vector<char>>& expected_records, std::function<void(int)> generate_event);

class _disable_crt_report_hook
{
  public:
    _disable_crt_report_hook() { previous_hook = _CrtSetReportHook(_ignore_report_hook); }
    ~_disable_crt_report_hook() { _CrtSetReportHook(previous_hook); }

  private:
    static int
    _ignore_report_hook(int reportType, char* message, int* returnValue)
    {
        UNREFERENCED_PARAMETER(reportType);
        UNREFERENCED_PARAMETER(message);
        // Don't show the debug window.
        *returnValue = 0;
        return TRUE;
    }
    _CRT_REPORT_HOOK previous_hook;
};

typedef struct _perf_buffer_test_context
{
    _perf_buffer_test_context();
    ~_perf_buffer_test_context();
    void
    unsubscribe();
    std::mutex lock;
    std::promise<void> perf_buffer_event_promise;
    struct perf_buffer* perf_buffer;
    const std::vector<std::vector<char>>* records;
    std::set<size_t> event_received;
    bool canceled;
    int matched_entry_count;
    int lost_entry_count;
    int test_event_count;
    int bad_records;
    bool doubled_data;
} perf_buffer_test_context_t;

void
perf_buffer_test_event_handler(_Inout_ void* ctx, int cpu, _In_opt_ const void* data, size_t size);

void
perf_buffer_api_test_helper(
    fd_t perf_buffer_map,
    std::vector<std::vector<char>>& expected_records,
    std::function<void(int)> generate_event,
    bool doubled_data = false);