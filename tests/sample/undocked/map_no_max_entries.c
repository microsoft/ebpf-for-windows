// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Sample eBPF program demonstrating use of BPF_F_NO_MAX_ENTRIES to create a
// hash map without a maximum entry limit.

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 2);
    __uint(map_flags, BPF_F_NO_MAX_ENTRIES);
} no_max_entries_map SEC(".maps");

SEC("sample_ext") int map_no_max_entries(sample_program_context_t* ctx)
{
    if (ctx->data_start + sizeof(uint32_t) > ctx->data_end) {
        return -1;
    }

    uint32_t key = *(uint32_t*)ctx->data_start;
    uint64_t value = (uint64_t)key * (uint64_t)key;

    return bpf_map_update_elem(&no_max_entries_map, &key, &value, 0);
}
