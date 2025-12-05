// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c divide_by_zero.c -o divide_by_zero_jit.o
//
// For bpf code: clang -target bpf -O2 -Werror -c divide_by_zero.c -o divide_by_zero.o
// this passes the checker

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
    __uint(type, BPF_MAP_TYPE_SAMPLE_ARRAY_MAP);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} sample_array_map SEC(".maps");

SEC("cgroup/connect4")
uint32_t
access_map(bpf_sock_addr_t* ctx)
{
    uint32_t key = 0;
    uint32_t* value = bpf_map_lookup_elem(&sample_array_map, &key);
    if (value) {
        (*value)++;
    }
    return 0;
}