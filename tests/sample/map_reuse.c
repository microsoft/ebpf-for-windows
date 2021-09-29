// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c map_reuse.c -o map_reuse.o
//
// For bpf code: clang -target bpf -O2 -Werror -c map_reuse.c -o map_reuse.o
// this passes the checker

#include "bpf_helpers.h"
#include "ebpf.h"

#define PIN_NONE 0
#define PIN_GLOBAL_NS 2
SEC("maps")
struct _ebpf_map_definition_in_file outer_map = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
    .pinning = PIN_GLOBAL_NS,
    // inner_map_idx refers to the map index in the same ELF object.
    .inner_map_idx = 1}; // (uint32_t)&inner_map

SEC("maps")
struct _ebpf_map_definition_in_file inner_map = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 1};

SEC("maps")
ebpf_map_definition_in_file_t port_map = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .pinning = PIN_GLOBAL_NS,
    .max_entries = 1};

SEC("xdp_prog") int lookup_update(struct xdp_md* ctx)
{
    uint32_t outer_key = 0;

    // Read value from inner map.
    void* inner_map = bpf_map_lookup_elem(&outer_map, &outer_key);
    if (inner_map) {
        uint32_t inner_key = 0;
        uint32_t* inner_value = (uint32_t*)bpf_map_lookup_elem(inner_map, &inner_key);
        if (inner_value) {
            // Update the value in port_map
            uint32_t key = 0;
            uint32_t value = (uint32_t)(*inner_value);
            bpf_map_update_elem(&port_map, &key, &value, 0);

            return *inner_value;
        }
    }
    return 0;
}
