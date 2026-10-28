// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Sample eBPF program using the legacy 32-byte map definition emitted before
// map_flags was added to _ebpf_map_definition_in_file.

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

typedef struct _legacy_map_definition
{
    ebpf_map_type_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t inner_map_idx;
    ebpf_pin_type_t pinning;
    uint32_t id;
    uint32_t inner_id;
} legacy_map_definition_t;

_Static_assert(sizeof(legacy_map_definition_t) == 32, "legacy map definition must remain 32 bytes");

SEC("maps")
legacy_map_definition_t legacy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 2,
};

SEC("sample_ext") int map_legacy_compat(sample_program_context_t* ctx)
{
    if (ctx->data_start + sizeof(uint32_t) > ctx->data_end) {
        return -1;
    }

    uint32_t key = *(uint32_t*)ctx->data_start;
    uint64_t value = (uint64_t)key * (uint64_t)key;

    return bpf_map_update_elem(&legacy_map, &key, &value, 0);
}
