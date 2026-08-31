// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Sample eBPF program demonstrating the default bounded hash map behavior.

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

SEC("maps")
struct _ebpf_map_definition_in_file max_entries_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 2,
};

SEC("sample_ext") int map_max_entries(sample_program_context_t* ctx)
{
    if (ctx->data_start + sizeof(uint32_t) > ctx->data_end) {
        return -1;
    }

    uint32_t key = *(uint32_t*)ctx->data_start;
    uint64_t value = (uint64_t)key * (uint64_t)key;

    return bpf_map_update_elem(&max_entries_map, &key, &value, 0);
}