// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdbool.h>
#include <stdint.h>
#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"

#define NO_FLAGS 0

#pragma clang section data = "maps"
ebpf_map_definition_t app_map = {
    .size = sizeof(ebpf_map_definition_t),
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(five_tuple_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 500};

#pragma clang section text = "flow"
void
AssociateFlowToContext(flow_md_t* context)
{
    if (context->flow_established_flag) {
        bpf_map_update_elem(&app_map, &context->five_tuple, &context->app_id, NO_FLAGS);
    } else { // flow deletion
        bpf_map_delete_elem(&app_map, &context->five_tuple);
    }
    return;
}