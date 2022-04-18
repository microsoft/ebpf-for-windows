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

SEC("maps")
struct bpf_map outer_map = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
    // inner_map_idx refers to the map index in the same ELF object.
    .inner_map_idx = 1}; // (uint32_t)&inner_map

SEC("maps")
struct bpf_map_def inner_map = {
    .type = BPF_MAP_TYPE_PROG_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 1};

SEC("xdp_prog") int caller(struct xdp_md* ctx)
{
    uint32_t index = 0;
    struct bpf_map* inner_map = (struct bpf_map*)bpf_map_lookup_elem(&outer_map, &index);

    bpf_tail_call(ctx, inner_map, 0);

    // If we get to here it means bpf_tail_call failed.
    return 6;
}

SEC("xdp_prog/0") int callee(struct xdp_md* ctx) { return 42; }
