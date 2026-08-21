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
#include "unique_handles.h"

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

/**
 * @brief RAII guard for legacy links created by bpf_prog_attach.
 *
 * bpf_prog_attach does not return a bpf_link handle, so the only way to
 * clean up is to call bpf_prog_detach2 with the same parameters. This
 * guard captures those parameters at attach time and calls detach in its
 * destructor, ensuring cleanup even when tests exit via exceptions or
 * SAFE_REQUIRE failures.
 */
class bpf_prog_attach_guard_t
{
  public:
    bpf_prog_attach_guard_t() = default;

    /**
     * @brief Attach a program and take ownership of detaching it.
     * @param prog_fd File descriptor of the program to attach.
     * @param attach_target Target (compartment ID) to attach to.
     * @param attach_type The BPF attach type.
     * @param flags Attach flags.
     */
    bpf_prog_attach_guard_t(int prog_fd, uint32_t attach_target, bpf_attach_type attach_type, uint32_t flags = 0)
        : _prog_fd(prog_fd), _attach_target(attach_target), _attach_type(attach_type)
    {
        _last_result = bpf_prog_attach(prog_fd, attach_target, attach_type, flags);
        _attached = (_last_result == 0);
    }

    ~bpf_prog_attach_guard_t() { detach(); }

    bpf_prog_attach_guard_t(const bpf_prog_attach_guard_t&) = delete;
    bpf_prog_attach_guard_t&
    operator=(const bpf_prog_attach_guard_t&) = delete;

    bpf_prog_attach_guard_t(bpf_prog_attach_guard_t&& other) noexcept
        : _prog_fd(other._prog_fd), _attach_target(other._attach_target), _attach_type(other._attach_type),
          _attached(other._attached), _last_result(other._last_result)
    {
        other._attached = false;
    }

    bpf_prog_attach_guard_t&
    operator=(bpf_prog_attach_guard_t&& other) noexcept
    {
        if (this != &other) {
            detach();
            _prog_fd = other._prog_fd;
            _attach_target = other._attach_target;
            _attach_type = other._attach_type;
            _attached = other._attached;
            _last_result = other._last_result;
            other._attached = false;
        }
        return *this;
    }

    /** @brief Manually detach. Safe to call multiple times. */
    int
    detach()
    {
        if (_attached) {
            _attached = false;
            return bpf_prog_detach2(_prog_fd, _attach_target, _attach_type);
        }
        return 0;
    }

    /** @brief Result of the bpf_prog_attach call (0 on success). */
    int
    result() const
    {
        return _last_result;
    }

    /** @brief Whether the program is currently attached. */
    bool
    attached() const
    {
        return _attached;
    }

  private:
    int _prog_fd{-1};
    uint32_t _attach_target{0};
    bpf_attach_type _attach_type{};
    bool _attached{false};
    int _last_result{-1};
};

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