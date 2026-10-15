// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "xdp_hooks.h"

SEC("maps/invalid_array_of_maps")
struct bpf_map_def invalid_array_of_maps = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint16_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
    .inner_map_idx = 1};

SEC("maps/inner_map")
struct bpf_map_def inner_map = {
    .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 1};

SEC("xdp")
int
invalid_array_of_maps_key_size(xdp_md_t* context)
{
    (void)context;
    return XDP_PASS;
}
