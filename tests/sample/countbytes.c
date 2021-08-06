// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdbool.h>
#include <stdint.h>
#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"

#define NO_FLAGS 0

#pragma clang section data = "maps"
ebpf_map_definition_t byte_map = {
    .size = sizeof(ebpf_map_definition_t),
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(five_tuple_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 500};

#pragma clang section text = "mac"
void
CountBytes(mac_md_t* context)
{
    uint64_t* byte_count = bpf_map_lookup_elem(&byte_map, &context->five_tuple);
    if (!byte_count) {
        bpf_map_update_elem(&byte_map, &context->five_tuple, context->packet_length, NO_FLAGS);
    } else {
        bpf_map_update_elem(&byte_map, &context->five_tuple, *byte_count + context->packet_length, NO_FLAGS);
    }
    return;
}