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

#define MAX_ENTRIES 1024

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} map_init SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_SAMPLE_ARRAY_MAP);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, MAX_ENTRIES);
} sample_map SEC(".maps");

SEC("sample_ext/prepare") int prepare(void* ctx)
{
    int key = 0;
    int* value = bpf_map_lookup_elem(&map_init, &key);
    if (value && *value < MAX_ENTRIES) {
        int i = *value;
        bpf_map_update_elem(&sample_map, &i, &i, BPF_ANY);
        *value += 1;
    }
    return 0;
}

SEC("sample_ext/read") int read(void* ctx)
{
    int key = bpf_get_prandom_u32() % MAX_ENTRIES;
    int* value = bpf_map_lookup_elem(&sample_map, &key);
    if (value) {
        return 0;
    }
    return 1;
}

SEC("sample_ext/update") int update(void* ctx)
{
    int key = bpf_get_prandom_u32() % MAX_ENTRIES;
    bpf_map_update_elem(&sample_map, &key, &key, BPF_ANY);
    return 0;
}

SEC("sample_ext/replace") int replace(void* ctx)
{
    int key = bpf_get_prandom_u32() % MAX_ENTRIES;
    (void)bpf_map_delete_elem(&sample_map, &key);
    (void)bpf_map_update_elem(&sample_map, &key, &key, BPF_ANY);
    return 0;
}
