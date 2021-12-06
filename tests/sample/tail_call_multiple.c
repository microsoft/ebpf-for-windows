// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"

SEC("maps")
struct bpf_map map = {sizeof(struct bpf_map), BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 10};

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
