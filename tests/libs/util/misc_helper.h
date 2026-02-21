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
 *
 * Sets the CPU in constructor if specified or in switch_cpu method.
 *
 * Restores the original CPU affinity in the destructor.
 */
struct scoped_cpu_affinity
{
    HANDLE thread_handle;    ///< Handle to the current thread.
    DWORD_PTR original_mask; ///< Original CPU affinity mask to restore on destruction.
    /**
     * @brief Initialize the object without setting CPU affinity.
     *
     * Call switch_cpu method to set CPU affinity after construction.
     */
    scoped_cpu_affinity() : thread_handle(GetCurrentThread()), original_mask(0) {}

    /**
     * @brief Initializes the object and sets CPU affinity to the specified CPU index.
     *
     * @param[in] i CPU index to set affinity to.
     */
    scoped_cpu_affinity(uint32_t i) : thread_handle(GetCurrentThread())
    {
        REQUIRE(i < (8 * sizeof(DWORD_PTR)));
        original_mask = SetThreadAffinityMask(thread_handle, (1ULL << i));
        REQUIRE(original_mask != 0);
    }

    /**
     * @brief Switch CPU affinity to the specified CPU index.
     *
     * Changes the CPU affinity of the current thread to the specified CPU index.
     * Can be called multiple times to switch between CPUs.
     *
     * The destructor will restore the original CPU affinity regardless of how many times this method is called.
     *
     * @param[in] i CPU index to set affinity to.
     */
    void
    switch_cpu(uint32_t i)
    {
        REQUIRE(i < (8 * sizeof(DWORD_PTR)));
        DWORD_PTR previous_mask = SetThreadAffinityMask(thread_handle, (1ULL << i));
        REQUIRE(previous_mask != 0);
        if (original_mask == 0) {
            original_mask = previous_mask;
        }
    }

    /**
     * @brief Destructor that restores the original CPU affinity.
     *
     * Restores the original CPU affinity mask if it was changed in the constructor or switch_cpu method.
     */
    ~scoped_cpu_affinity()
    {
        if (original_mask != 0) {
            SetThreadAffinityMask(thread_handle, original_mask);
        }
    }
};