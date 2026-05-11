// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Bounds check result stored in a flag variable; verifier loses correlation at join.
// Expected error: Upper bound must be at most packet_size (valid_access(..., width=4) for read)
// Pattern: §4.11 - Lost Correlations in Computed Branches

#include "bpf_helpers.h"
#include "xdp_hooks.h"

SEC("xdp")
void
dependent_read(xdp_md_t* ctx)
{
    // Use inline asm with 64-bit reads for Windows xdp_md_t (void* fields)
    asm volatile("r5 = 0");
    asm volatile("r2 = *(u64 *)(r1 + 0)"); // data (void*, offset 0, 8 bytes)
    asm volatile("r3 = *(u64 *)(r1 + 8)"); // data_end (void*, offset 8, 8 bytes)
    asm volatile("r1 = r2");
    asm volatile("r2 += 4");
    asm volatile("if r2 > r3 goto +1");    // bounds check: data + 4 > data_end?
    asm volatile("r5 = 1");                // flag: bounds check passed
    asm volatile("if r5 == 0 goto +1");    // BUG: verifier loses correlation
    asm volatile("r0 = *(u32 *)(r1 + 0)"); // packet read guarded only by flag
    asm volatile("r0 = 0");
}
