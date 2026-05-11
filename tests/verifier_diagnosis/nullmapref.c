// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Null pointer dereference after bpf_map_lookup_elem without null check.
// Expected error: Possible null access (valid_access(r0.offset, width=4) for write)
// Pattern: §4.4 - Null Pointer After Map Lookup

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
    uint32_t* value = bpf_map_lookup_elem(&test_map, &key);
    *value = 1; // BUG: value may be NULL
    return 0;
}
