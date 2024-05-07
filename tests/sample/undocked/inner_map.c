// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c inner_map.c -o inner_map.o
//
// For bpf code: clang -target bpf -O2 -Werror -c inner_map.c -o inner_map.o
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
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, uint32_t);
    __uint(max_entries, 1);
    __array(
        values, struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __type(key, uint32_t);
            __type(value, uint32_t);
            __uint(max_entries, 1);
        });
} outer_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1024);
} inner_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, uint16_t);
    __uint(max_entries, 1);
    __array(values, inner_map);
} outer_map2 SEC(".maps");

SEC("sample_ext") int lookup_update(sample_program_context_t* ctx)
{
    uint32_t outer_key = 0;
    uint16_t outer_key2 = 0;
    void* inner_map = NULL;
    void* inner_map2 = NULL;

    // Read value from inner map.
    inner_map = bpf_map_lookup_elem(&outer_map, &outer_key);
    if (inner_map) {
        uint32_t inner_key = 0;
        uint32_t* inner_value = (uint32_t*)bpf_map_lookup_elem(inner_map, &inner_key);
        if (inner_value) {
            // Update value in inner map.
            *inner_value = 1;
            return 0;
        }
    }

    // Read value from inner map.
    inner_map2 = bpf_map_lookup_elem(&outer_map2, &outer_key2);
    if (inner_map2) {
        uint32_t inner_key = 0;
        uint32_t* inner_value = (uint32_t*)bpf_map_lookup_elem(inner_map, &inner_key);
        if (inner_value) {
            // Update value in inner map.
            *inner_value = 1;
            return 0;
        }
    }

    return 1;
}
