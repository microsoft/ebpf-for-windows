// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "xdp_hooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint16_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} invalid_array_map SEC(".maps");

SEC("xdp")
int
invalid_array_map_key_size(xdp_md_t* context)
{
    (void)context;
    return XDP_PASS;
}
