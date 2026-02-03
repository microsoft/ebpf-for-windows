// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @brief Miscellaneous test helper functions.
 */

#pragma once
#include <atomic>

/**
 * @brief Helper function to get a 64-bit number where high-order 32 bits contain the process ID and
 * the remaining 32 bits contains the thread ID.
 */
uint64_t
get_current_pid_tgid();

struct test_failure : std::exception
{
    test_failure(const std::string& message) : message(message) {}
    std::string message;
};

// All tests that want to use this macro must define a thread local bool in its test. For example:
// thread_local bool _is_main_thread = false;
#define SAFE_REQUIRE(x)                                               \
    if (_is_main_thread) {                                            \
        REQUIRE(x);                                                   \
    } else {                                                          \
        if (!(x)) {                                                   \
            throw test_failure("Condition failed" + std::string(#x)); \
        }                                                             \
    }

/**
 * @brief RAII class to set CPU affinity for the current thread.
 */
struct scoped_cpu_affinity
{
    HANDLE thread_handle;
    DWORD_PTR previous_mask;
    bool affinity_set;
    scoped_cpu_affinity(uint32_t i) : affinity_set(false)
    {
        thread_handle = GetCurrentThread();
        previous_mask = SetThreadAffinityMask(thread_handle, (1ULL << i));
        REQUIRE(previous_mask != 0);
        affinity_set = true;
    }
    ~scoped_cpu_affinity()
    {
        if (affinity_set) {
            SetThreadAffinityMask(thread_handle, previous_mask);
        }
    }
};