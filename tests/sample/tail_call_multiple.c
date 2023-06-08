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

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 10);
} map SEC(".maps");

SEC("xdp_prog") int caller(struct xdp_md* ctx)
{
    uint32_t index = 0;

    // Callee0 is at index 0
    bpf_tail_call(ctx, &map, index);

    // If we get to here it means bpf_tail_call failed.
    return 1;
}

SEC("xdp_prog/0") int callee0(struct xdp_md* ctx)
{
    uint32_t index = 9;

    // Callee1 is at index 9.
    bpf_tail_call(ctx, &map, index);

    // If we get to here it means bpf_tail_call failed.
    return 2;
}

SEC("xdp_prog/1") int callee1(struct xdp_md* ctx) { return 3; }
