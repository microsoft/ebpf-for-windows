// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"

SEC("maps")
struct bpf_map outer_map = {
    .size = sizeof(struct bpf_map),
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1};

SEC("xdp_prog") int caller(struct xdp_md* ctx)
{
    uint32_t index = 0;
    struct bpf_map* inner_map = (struct bpf_map*)bpf_map_lookup_elem(&outer_map, &index);

    bpf_tail_call(ctx, inner_map, 0);

    // If we get to here it means bpf_tail_call failed.
    return 6;
}

SEC("xdp_prog/0") int callee(struct xdp_md* ctx) { return 42; }
