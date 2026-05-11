// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Passing a regular array map to bpf_tail_call (requires PROG_ARRAY).
// Expected error: Invalid type (r2.type == map_fd_programs)
// Pattern: §4.6 - Type Mismatch

#include "bpf_helpers.h"
#include "xdp_hooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} map SEC(".maps");

SEC("xdp")
int
caller(xdp_md_t* ctx)
{
    // BUG: map is BPF_MAP_TYPE_ARRAY, not BPF_MAP_TYPE_PROG_ARRAY
    long error = bpf_tail_call(ctx, &map, 0);
    return (int)error;
}
