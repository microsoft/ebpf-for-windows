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

int
recurse(sample_program_context_t* ctx);

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);
    __uint(key_size, sizeof(uint32_t));
    __array(values, int(sample_program_context_t* ctx));
} map SEC(".maps") = {
    // First and last entries are NULL to test that we can handle cases where
    // the initial values are not at the beginning of the array.
    .values =
        {
            NULL,
            recurse,
            NULL,
        },
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
} canary SEC(".maps");

SEC("sample_ext") int recurse(sample_program_context_t* ctx)
{
    uint32_t key = 0;
    uint32_t* value;

    // Get the number of times we've been called.
    value = (uint32_t*)bpf_map_lookup_elem(&canary, &key);
    if (!value) {
        return 0;
    }

    bpf_printk("recurse: *value=%d\n", *value);

    // Record that we've been called.
    (*value)++;

    // Recursively call this program.
    return bpf_tail_call(ctx, &map, 1);
}
