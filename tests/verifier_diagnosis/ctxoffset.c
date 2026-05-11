// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Context pointer modified before passing to helper that requires ctx_offset==0.
// Expected error: Nonzero context offset (r1.ctx_offset == 0)
// Pattern: §4.10 - Context Field Bounds Violation (ctx_offset variant)

#include "bpf_helpers.h"
#include "xdp_hooks.h"

SEC("xdp")
int
func(xdp_md_t* ctx)
{
    // BUG: offsetting ctx before passing to helper
    xdp_md_t* bad_ctx = (xdp_md_t*)((char*)ctx + 8);
    int result = bpf_xdp_adjust_head(bad_ctx, 4);
    return result;
}
