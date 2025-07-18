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

// Goal of this program is to demonstrate how multiple maps can be updated atomically
// so that the BPF program uses a consistent set of maps (either the old or the new maps).

// This is done by using an outer map that contains two inner maps, one active and one inactive.
// The active map is determined by the active_map_index variable, which is read atomically.
// The BPF program looks up elements in the active inner map and uses them to look up elements
// in the other active inner map. If any of the lookups fail, it increments a failure counter
// in the failure_stats map. This allows us to track failures when the inner map lookup fails,
// which indicates a bug in the synchronization logic.

// Static variable to hold the index of the active map. Alternates between 0 and 1.
static uint32_t active_map_index = 0;

// First outer map contains two inner maps of type BPF_MAP_TYPE_ARRAY (active and inactive).
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
} outer_map_1 SEC(".maps");

// Second outer map contains two inner maps of type BPF_MAP_TYPE_HASH (active and inactive).
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 2);
    __array(
        values, struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, uint32_t);
            __type(value, uint32_t);
            __uint(max_entries, 1);
        });
} outer_map_2 SEC(".maps");

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
    // Read the active map index atomically to ensure we get a consistent view of the maps.
    uint32_t active_map_index_value = READ_ONCE_UINT32(&active_map_index);

    // Get the active inner maps from the outer maps using the active_map_index.
    void* inner_map_1 = bpf_map_lookup_elem(&outer_map_1, &active_map_index_value);
    void* inner_map_2 = bpf_map_lookup_elem(&outer_map_2, &active_map_index_value);

    // If either inner map lookup fails, increment the failure counter and return.
    if (!inner_map_1 || !inner_map_2) {
        uint32_t* failure_value = bpf_map_lookup_elem(&failure_stats, &zero_key);
        if (failure_value) {
            (*failure_value)++;
        }
        return 1;
    }

    // Look up an element in the active inner map 1.
    uint32_t* value_1 = bpf_map_lookup_elem(inner_map_1, &zero_key);
    if (!value_1) {
        uint32_t* failure_value = bpf_map_lookup_elem(&failure_stats, &zero_key);
        if (failure_value) {
            (*failure_value)++;
        }
        return 2;
    }

    // Use the value from inner_map_1 to look up in inner_map_2.
    uint32_t* value_2 = bpf_map_lookup_elem(inner_map_2, value_1);
    if (!value_2) {
        uint32_t* failure_value = bpf_map_lookup_elem(&failure_stats, &zero_key);
        if (failure_value) {
            (*failure_value)++;
        }
        return 3;
    }

    return 0;
}
