// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Reading 8 bytes from a 4-byte map value.
// Expected error: Upper bound must be at most r1.shared_region_size (valid_access(..., width=8) for read)
// Pattern: §4.2 - Unbounded Access (shared memory variant)

#include "bpf_helpers.h"
#include "xdp_hooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} map SEC(".maps");

SEC("xdp")
int
func(xdp_md_t* ctx)
{
    uint32_t key = 1;
    uint64_t* ptr = (uint64_t*)bpf_map_lookup_elem(&map, &key);
    if (ptr == 0) {
        return 0;
    }
    uint64_t i = *ptr; // BUG: reading 8 bytes from 4-byte value
    return (uint32_t)i;
}
