// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Thread local storage to track recursing from the low memory callback.
 */
inline static thread_local int _ebpf_recursion_guard_count = 0;

/**
 * @brief Class to automatically increment and decrement the recursion count.
 */
typedef class _ebpf_recursion_guard
{
  public:
    _ebpf_recursion_guard() { _ebpf_recursion_guard_count++; }
    ~_ebpf_recursion_guard() { _ebpf_recursion_guard_count--; }

    /**
     * @brief Return true if the current thread is recursing from the low memory callback.
     * @retval true
     * @retval false
     */
    bool
    is_recursing()
    {
        return (_ebpf_recursion_guard_count > 1);
    }
} ebpf_recursion_guard_t;