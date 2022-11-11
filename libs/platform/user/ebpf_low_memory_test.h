// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <fstream>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "ebpf_platform.h"

/**
 * @brief This class is used to track memory allocations and fail the first allocation for
 * a specific stack. Increasing the number of stack frames examined will increase the
 * accuracy of the test, but also increase the time it takes to run the test.
 */
typedef class _ebpf_low_memory_test
{
  public:
    /**
     * @brief Construct a new ebpf low memory test object.
     * @param[in] stack_depth The number of stack frames to compare when tracking allocations.
     */
    _ebpf_low_memory_test(size_t stack_depth);

    /**
     * @brief Destroy the ebpf low memory test object.
     *
     */
    ~_ebpf_low_memory_test();

    /**
     * @brief Test to see if the allocator should fail this allocation.
     *
     * @retval true Fail the allocation.
     * @retval false Don't fail the allocation.
     */
    bool
    fail_stack_allocation();

  private:
    /**
     * @brief Compute a hash over the current stack.
     */
    struct _stack_hasher
    {
        size_t
        operator()(const std::vector<uintptr_t>& key) const
        {
            size_t hash_value = 0;
            for (const auto value : key) {
                hash_value ^= std::hash<uintptr_t>{}(value);
            }
            return hash_value;
        }
    };

    /**
     * @brief Determine if this allocation path is new.
     * If it is new, then fail the allocation, add it to the set of known
     * allocation paths and return true.
     */
    bool
    is_new_stack();

    /**
     * @brief Write the current stack to the log file.
     */
    void
    log_stack_trace(const std::vector<uintptr_t>& canonical_stack, const std::vector<uintptr_t>& stack);

    /**
     * @brief Load the list of known allocation paths from the log file.
     */
    void
    load_allocation_log();

    /**
     * @brief The base address of the current process.
     */
    uintptr_t _base_address = 0;

    /**
     * @brief The iteration number of the current test pass.
     */
    size_t _iteration = 0;

    /**
     * @brief The log file for allocations that have been failed.
     */
    std::ofstream _log_file;

    /**
     * @brief The set of known allocation paths.
     */
    std::unordered_set<std::vector<uintptr_t>, _stack_hasher> _allocation_hash;

    /**
     * @brief The mutex to protect the set of known allocation paths.
     */
    std::mutex _mutex;

    size_t _stack_depth;
} ebpf_low_memory_test_t;
