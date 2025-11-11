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

// Test eBPF program for EBPF_PROGRAM_TYPE_SAMPLE implemented in
// the Sample eBPF extension.

#include "sample_common_routines.h"
#include "sample_ext_helpers.h"
#include "sample_test_common.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 1);
} test_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 10);
} prog_array_map SEC(".maps");

__attribute__((always_inline)) void
increment_value()
{
    uint32_t key = 0;

    uint32_t* value = bpf_map_lookup_elem(&test_map, &key);
    // Increment value if found.
    if (value) {
        *value += 1;
    }
}

SEC("sample_ext")
int
test_program_entry(sample_program_context_t* context)
{
    increment_value();

    bpf_tail_call(context, &prog_array_map, 0);

    return 1;
}

SEC("sample_ext")
int
tail_call(sample_program_context_t* context)
{
    increment_value();

    return 0;
}
