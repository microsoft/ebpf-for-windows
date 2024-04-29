// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c map_reuse_2.c -o map_reuse_2.o
//
// For bpf code: clang -target bpf -O2 -Werror -c map_reuse_2.c -o map_reuse_2.o
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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} inner_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, uint32_t);
    __uint(max_entries, 1);
    __type(value, uint32_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, inner_map);
} outer_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} port_map SEC(".maps");

SEC("sample_ext") int lookup_update(sample_program_context_t* ctx)
{
    uint32_t outer_key = 0;

    // Read value from inner map.
    void* inner_map = bpf_map_lookup_elem(&outer_map, &outer_key);
    if (inner_map) {
        uint32_t inner_key = 0;
        uint32_t* inner_value = (uint32_t*)bpf_map_lookup_elem(inner_map, &inner_key);
        if (inner_value) {
            // Update the value in port_map.
            uint32_t key = 0;
            uint32_t value = (uint32_t)(*inner_value);
            bpf_map_update_elem(&port_map, &key, &value, 0);

            return *inner_value;
        }
    }
    return 0;
}
