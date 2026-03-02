// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Storing a context pointer into a map value (information leak).
// Expected error: Illegal map update with a non-numerical value (within(r3:value_size(r1)))
// Pattern: §4.9 - Map Key/Value Size Mismatch (non-numeric variant)

#include "bpf_helpers.h"
#include "xdp_hooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} map SEC(".maps");

SEC("xdp")
int
func(xdp_md_t* ctx)
{
    uint32_t key = 0;
    return bpf_map_update_elem(&map, &key, &ctx, 0); // BUG: ctx is a pointer, not numeric
}
