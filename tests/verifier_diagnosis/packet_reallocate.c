// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: Using packet pointers after a helper that may reallocate the packet buffer.
// Expected error: Invalid type (r7.type in {ctx, stack, packet, shared})
// Pattern: §4.12 - Stale Pointer After Reallocation

#include "bpf_helpers.h"
#include "xdp_hooks.h"

SEC("xdp")
int
reallocate_invalidates(xdp_md_t* ctx)
{
    void* data_end = (void*)ctx->data_end;
    void* data = (void*)ctx->data;
    if ((char*)data + sizeof(int) > (char*)data_end)
        return 1;
    int value = *(int*)data;
    *(int*)data = value + 1;
    bpf_xdp_adjust_head(ctx, 4); // Reallocates packet buffer
    // BUG: data and data_end are now stale
    value = *(int*)data;
    *(int*)data = value + 1;
    return 0;
}
