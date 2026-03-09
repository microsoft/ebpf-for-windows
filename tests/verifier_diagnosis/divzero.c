// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Division by a value that could be zero (from map lookup).
// Expected error: Possible division by zero
// Pattern: §4.8 - Division by Zero
// Note: Requires --no-division-by-zero flag (verifier allows div-by-zero by default)

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
test_divzero(xdp_md_t* ctx)
{
    uint32_t key = 1;
    uint32_t* divisor_ptr = bpf_map_lookup_elem(&test_map, &key);
    if (!divisor_ptr) {
        return 0;
    }
    uint32_t result = 100 / *divisor_ptr; // BUG: *divisor_ptr can be 0
    return result;
}
