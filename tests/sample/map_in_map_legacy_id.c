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

#define INNER_MAP_ID 10

SEC("maps/outer_map")
struct bpf_map_def outer_map = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
    // inner_id refers to the id of the inner map in the same ELF object.
    .inner_id = INNER_MAP_ID}; // (uint32_t)&inner_map

SEC("maps/inner_map")
struct bpf_map_def inner_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
    .id = INNER_MAP_ID};

SEC("xdp_prog") int lookup(struct xdp_md* ctx)
{
    uint32_t outer_key = 0;
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
