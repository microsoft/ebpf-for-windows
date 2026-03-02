// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Loop bound comes from map value — verifier cannot prove termination.
// Expected error: Loop counter is too large
// Pattern: §4.7 - Infinite Loop / Termination Failure
// Note: Requires check_termination:true (MCP) or --termination (CLI)

#include "bpf_helpers.h"
#include "xdp_hooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} test_map SEC(".maps");

SEC("xdp")
int
test_infinite_loop(xdp_md_t* ctx)
{
    uint32_t key = 0;
    uint32_t* bound_ptr = bpf_map_lookup_elem(&test_map, &key);
    if (!bound_ptr) {
        return 0;
    }
    uint32_t bound = *bound_ptr;
    uint32_t sum = 0;
    for (uint32_t i = 0; i < bound; i++) { // BUG: bound is unbounded
        sum += i;
        asm volatile("" : "+r"(sum)); // prevent clang from reducing to closed-form
    }
    return sum;
}
