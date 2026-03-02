// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Bounded loop that compiler transforms to unprovable form (i < 1000 → i != 1000).
// Expected error: Could not prove termination
// Pattern: §4.7 - Infinite Loop / Termination Failure (compiler transformation variant)
// Note: Requires --termination flag

#include "bpf_helpers.h"
#include "xdp_hooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1024);
} counter_map SEC(".maps");

SEC("xdp")
int
test_bounded_loop(xdp_md_t* ctx)
{
    for (int i = 0; i < 1000; i++) {
        uint32_t key = i;
        uint32_t* slot = bpf_map_lookup_elem(&counter_map, &key);
        if (slot) {
            *slot += 1;
        }
    }
    return 0;
}
