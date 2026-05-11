// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Packet access without sufficient bounds check.
// Expected error: Upper bound must be at most packet_size (valid_access(..., width=4) for read)
// Pattern: §4.2 - Unbounded Packet Access

#include "bpf_helpers.h"
#include "xdp_hooks.h"

SEC("xdp")
int
read_write_packet_start(xdp_md_t* ctx)
{
    void* data_end = (void*)ctx->data_end;
    void* data = (void*)ctx->data;
    if (data > data_end) // BUG: wrong comparison, doesn't establish minimum packet size
        return 1;
    int value = *(int*)data; // BUG: data could equal data_end (zero-length)
    *(int*)data = value + 1;
    return 0;
}
