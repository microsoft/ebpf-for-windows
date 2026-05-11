// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Adding two pointers together (only pointer + number is allowed).
// Expected error: Invalid type (r<N>.type == number)
// Pattern: §4.6 - Pointer Arithmetic with Non-Number

#include "bpf_helpers.h"
#include "xdp_hooks.h"

SEC("xdp")
int
test_ptr_arith(xdp_md_t* ctx)
{
    void* data_end = (void*)ctx->data_end;
    void* data = (void*)ctx->data;
    // BUG: adding two pointers — only pointer + number is valid
    void* bad_ptr = (void*)((long)data + (long)data_end);
    if (bad_ptr > data_end) {
        return 1;
    }
    return 0;
}
