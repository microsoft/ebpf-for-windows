// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Writing beyond stack frame boundary via too-wide store.
// Expected error: Upper bound must be at most EBPF_TOTAL_STACK_SIZE
// Pattern: §4.3 - Stack Out-of-Bounds Access

#include "bpf_helpers.h"
#include "xdp_hooks.h"

SEC("xdp")
int
func(xdp_md_t* ctx)
{
    // Write 8 bytes at stack offset -1: bytes [-1..+6] relative to frame end.
    // Only byte -1 is within the frame; bytes 0..+6 exceed EBPF_TOTAL_STACK_SIZE.
    asm volatile("r1 = r10");
    asm volatile("r1 += -1");
    asm volatile("r2 = 0");
    asm volatile("*(u64 *)(r1 + 0) = r2");
    asm volatile("r0 = 0");
    return 0;
}
