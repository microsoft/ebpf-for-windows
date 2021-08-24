// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

SEC("maps")
struct bpf_map outer_map = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
    // inner_map_idx refers to the map index in the same ELF object.
    .inner_map_idx = 1}; // (uint32_t)&inner_map

SEC("maps")
struct bpf_map inner_map = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 1};

SEC("xdp_prog") int caller(struct xdp_md* ctx)
{
    uint32_t outer_key = 0;
    void* nolocal_lru_map = bpf_map_lookup_elem(&outer_map, &outer_key);
    if (nolocal_lru_map) {
        uint32_t inner_key = 0;
        uint32_t* value = (uint32_t*)bpf_map_lookup_elem(nolocal_lru_map, &inner_key);
        if (value) {
            return *(uint32_t*)value;
        }
    }
    return 0;
}
