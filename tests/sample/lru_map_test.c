// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// eBPF program for testing LRU map behavior with kernel-mode access.
// This program performs lookups on an LRU hash map to verify that
// kernel-mode lookups affect LRU state (unlike user-mode lookups).

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 100);
} lru_map SEC(".maps");

SEC("bind")
bind_action_t
lru_lookup_program(bind_md_t* context)
{
    // Look up keys in LRU map starting from context->process_id (start key).
    uint32_t key = (uint32_t)context->process_id;
    uint64_t num_keys = (uint64_t)context->socket_address_length;
    if (num_keys >= 250) { // Limit for verification.
        return (bind_action_t)-1;
    }
    uint32_t found_count = 0;
    for (uint64_t i = 0; i < num_keys; i++) {
        uint32_t* value = bpf_map_lookup_elem(&lru_map, &key);
        if (value != NULL) {
            found_count++;
        }
        key++;
    }

    // Return number of keys found (cast to bind_action_t).
    return (bind_action_t)found_count;
}
