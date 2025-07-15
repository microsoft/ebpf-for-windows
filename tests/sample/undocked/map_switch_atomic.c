// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

static uint32_t active_map_index = 0;

// Outer map that contains two inner maps, one active and one inactive.
// The active_map_index variable is used to determine which inner map to use.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 2);
    __array(
        values, struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __type(key, uint32_t);
            __type(value, uint32_t);
            __uint(max_entries, 1);
        });
} outer_map SEC(".maps");

// Stats map to track failures when the inner map lookup fails.
// Inner map lookup failures indicate a bug in the synchronization logic.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} failure_stats SEC(".maps");

/**
 * READ_ONCE_UINT32 - A function to read a volatile uint32_t value.
 * This function is marked as always_inline to ensure that it is inlined
 * at the call site, which can help with performance and code size.
 *
 * @param[in] ptr Pointer to the volatile uint32_t value to read.
 * @return The value read from the pointer.
 */
inline uint32_t __attribute__((always_inline))
READ_ONCE_UINT32(const volatile uint32_t* ptr)
{
    uint32_t value;
    // Use a volatile read to ensure that the compiler does not optimize this away.
    // This is a simple read operation that should not be optimized out.
    value = *ptr;
    return value;
}

SEC("sample_ext") int lookup(sample_program_context_t* ctx)
{
    uint32_t zero_key = 0;
    uint32_t active_map_index_value = READ_ONCE_UINT32(&active_map_index);
    void* inner_map = bpf_map_lookup_elem(&outer_map, &active_map_index_value);
    if (!inner_map) {
        uint32_t* failure_value = bpf_map_lookup_elem(&failure_stats, &zero_key);
        if (failure_value) {
            (*failure_value)++;
        }
        return 1;
    }
    return 0;
}
