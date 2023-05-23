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
struct bpf_map map = {BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

SEC("maps") struct bpf_map canary = {BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

SEC("xdp_prog") int recurse(struct xdp_md* ctx)
{
    uint32_t key = 0;
    uint32_t* value;

    // Get the number of times we've been called.
    value = (uint32_t*)bpf_map_lookup_elem(&canary, &key);
    if (!value) {
        return 0;
    }

    bpf_printk("recurse: *value=%d\n", *value);

    // Record that we've been called.
    (*value)++;

    // Recursively call this program.
    return bpf_tail_call(ctx, &map, 0);
}
