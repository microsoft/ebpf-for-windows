// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Passing an arithmetic-modified map pointer to bpf_map_lookup_elem.
// Expected error: Invalid type (r1.type in {number, ctx, stack, packet, shared})
// Pattern: §4.6 - Type Mismatch (using map_fd where pointer is expected)

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
test_repro(xdp_md_t* ctx)
{
    uint32_t key = 1;
    typeof(test_map)* map = &test_map;
    // BUG: arithmetic on map fd — map_fd + 1 is invalid
    uint32_t* value = bpf_map_lookup_elem(map + 1, &key);
    return (value != 0);
}
