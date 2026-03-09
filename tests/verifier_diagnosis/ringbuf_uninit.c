// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Passing uninitialized stack memory to a helper function.
// Expected error: Stack content is not numeric (valid_access(..., width=r3) for read)
// Pattern: §4.13 - Non-Numeric Stack Content

#include "bpf_helpers.h"
#include "xdp_hooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ring_buffer SEC(".maps");

SEC("xdp")
int
test(xdp_md_t* ctx)
{
    uint64_t test; // BUG: uninitialized
    bpf_ringbuf_output(&ring_buffer, &test, sizeof(test), 0);
    return 0;
}
