// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Storing a context pointer as a map key (information leak).
// Expected error: Illegal map update with a non-numerical value (within(r2:key_size(r1)))
// Pattern: §4.9 - Map Key/Value Size Mismatch (non-numeric variant, key)

#include "bpf_helpers.h"
#include "xdp_hooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint64_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} map SEC(".maps");

SEC("xdp")
int
func(xdp_md_t* ctx)
{
    uint32_t value = 0;
    // BUG: using pointer (ctx) as map key — leaks kernel address
    return bpf_map_update_elem(&map, &ctx, &value, 0);
}
