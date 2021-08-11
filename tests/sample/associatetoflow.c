// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdbool.h>
#include <stdint.h>
#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"

#define NO_FLAGS 0

#pragma clang section data = "maps"
ebpf_map_definition_t app_map = {
    .size = sizeof(ebpf_map_definition_t), .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(five_tuple_t), .value_size = sizeof(uint8_t[64]), .max_entries = 500};

#pragma clang section text = "flow"
void AssociateFlowToContext(flow_md_t* context)
{
    five_tuple_t key = context->five_tuple;
    uint8_t value[64];
    int index;

    for (index = 0; index < 64; index++) {
        if ((context->app_id_start + index) >= context->app_id_end)
        {
            break;
        }
        value[index] = context->app_id_start[index];
    }
    
    if (context->flow_established_flag)
    {
        bpf_map_update_elem(&app_map, &key, &value, NO_FLAGS);
    }
    else
    { // flow deletion
        bpf_map_delete_elem(&app_map, &key);
    }
    return;
}