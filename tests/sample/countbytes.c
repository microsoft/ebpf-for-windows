// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdbool.h>
#include <stdint.h>
#include "ebpf_helpers.h"
#include "ebpf.h"

#define NO_FLAGS 0

#pragma clang section data = "maps"
ebpf_map_definition_t byte_map = {
    .size = sizeof(ebpf_map_definition_t), .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(five_tuple_t), .value_size = sizeof(uint64_t), .max_entries = 500};

mac_hook_t CountBytes;

#pragma clang section text = "mac"
int CountBytes(mac_md_t* context)
{
    five_tuple_t key = context->five_tuple;
    uint64_t value = context->packet_length;
    uint64_t* byte_count = bpf_map_lookup_elem(&byte_map, &key);

    if (!byte_count)
    {
        bpf_map_update_elem(&byte_map, &key, &value, NO_FLAGS);
    }
    else
    {
        value = *byte_count + value;
        bpf_map_update_elem(&byte_map, &key, &value, NO_FLAGS);
    }

    return 0;
}