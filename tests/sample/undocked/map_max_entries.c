// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Sample eBPF program demonstrating the default bounded hash map behavior.

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 2);
} max_entries_map SEC(".maps");

SEC("sample_ext") int map_max_entries(sample_program_context_t* ctx)
{
    if (ctx->data_start + sizeof(uint32_t) > ctx->data_end) {
        return -1;
    }

    uint32_t key = *(uint32_t*)ctx->data_start;
    uint64_t value = (uint64_t)key * (uint64_t)key;

    return bpf_map_update_elem(&max_entries_map, &key, &value, 0);
}