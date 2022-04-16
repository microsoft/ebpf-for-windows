// Copyright (c) Microsoft Corporation
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

SEC("maps")
struct bpf_map_def outer_map = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
    .pinning = PIN_GLOBAL_NS,
    // inner_map_idx refers to the map index in the same ELF object.
    .inner_map_idx = 1}; // (uint32_t)&inner_map

SEC("maps")
struct bpf_map_def inner_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
    .pinning = PIN_GLOBAL_NS};

SEC("maps")
struct bpf_map_def port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .pinning = PIN_GLOBAL_NS,
    .max_entries = 1};

SEC("xdp_prog") int lookup_update(struct xdp_md* ctx)
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
