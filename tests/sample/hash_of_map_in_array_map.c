// Copyright (c) Microsoft Corporation
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

#define LB_MAP_MAX_ENTRIES 65536

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 1);
} inner_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, uint16_t);
    __type(value, uint32_t);
    __uint(max_entries, LB_MAP_MAX_ENTRIES);
    /* Inner map definition */
    __array(values, inner_map);
} outer_map SEC(".maps") = {
    .values = {&inner_map},
};

SEC("xdp_prog") int lookup(struct xdp_md* ctx)
{
    uint16_t outer_key = 0;
    void* inner_map = bpf_map_lookup_elem(&outer_map, &outer_key);
    if (inner_map) {
        uint32_t inner_key = 0;
        uint32_t* value = (uint32_t*)bpf_map_lookup_elem(inner_map, &inner_key);
        if (value) {
            return *(uint32_t*)value;
        }
    }
    return 0;
}