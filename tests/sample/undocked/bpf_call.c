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

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, 2);
    __uint(value_size, 4);
    __uint(max_entries, 512);
} map SEC(".maps");

SEC("sample_ext") int func(sample_program_context_t* ctx)
{
    uint32_t key = 0;
    uint32_t value = 42;
    int result = bpf_map_update_elem(&map, &key, &value, 0);
    return result;
}
