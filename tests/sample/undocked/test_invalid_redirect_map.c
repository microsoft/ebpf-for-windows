// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Negative test program for the global virtual bpf_redirect_map helper.
//
// This program is a bind program type, which does NOT implement the optional
// global virtual bpf_redirect_map helper. Loading it should therefore fail,
// since there is no implementation of bpf_redirect_map for this program type.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 64);
} redirect_map SEC(".maps");

SEC("bind")
int
test_invalid_redirect_map(bind_md_t* ctx)
{
    (void)ctx;

    // Try to call the bpf_redirect_map helper function.
    // This should fail because the bind program type does not implement bpf_redirect_map.
    intptr_t result = bpf_redirect_map(&redirect_map, 0, 0);

    bpf_printk("redirect_map result: %d\n", (int)result);

    return 0;
}
