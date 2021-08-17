// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// All of this file is cross-platform except the following
// two includes.  TODO: make the include filename(s) also be
// cross-platform for eBPF program portability.
#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"

__attribute__((section("maps"), used)) struct bpf_map outer_map = {.size = sizeof(struct bpf_map),
                                                                   .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
                                                                   .key_size = sizeof(uint32_t),
                                                                   .value_size = sizeof(uint32_t),
                                                                   .max_entries = 1};

__attribute__((section("xdp_prog"), used)) int
caller(struct xdp_md* ctx)
{
    uint32_t index = 0;
    struct bpf_map* inner_map = (struct bpf_map*)bpf_map_lookup_elem(&outer_map, &index);

    bpf_tail_call(ctx, inner_map, 0);

    // If we get to here it means bpf_tail_call failed.
    return 6;
}

__attribute__((section("xdp_prog/0"), used)) int
callee(struct xdp_md* ctx)
{
    return 42;
}
