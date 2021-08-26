// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdbool.h>
#include <stdint.h>
#include "ebpf_helpers.h"
#include "ebpf.h"

#define NO_FLAGS 0
#define NAME_SIZE 64

typedef struct _app_name
{
    uint8_t name[64];
} app_name_t;

#pragma clang section data = "maps"
ebpf_map_definition_t app_map = {
    .size = sizeof(ebpf_map_definition_t), .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(five_tuple_t), .value_size = sizeof(app_name_t), .max_entries = 500};

flow_hook_t AssociateFlowToContext;

#pragma clang section text = "flow"
int AssociateFlowToContext(flow_md_t* context)
{
    five_tuple_t key = context->five_tuple;
    app_name_t* entry;
    app_name_t value = {0};
    int index;

    // Flow Deleted
    if (!context->flow_established_flag)
    {
        bpf_map_delete_elem(&app_map, &key);
    }
    else // Flow Established
    {
        bpf_map_update_elem(&app_map, &key, &value, NO_FLAGS);
        entry = bpf_map_lookup_elem(&app_map, &key);
        if (!entry)
        {
            return 1;
        }
        if (!context->app_name_start || !context->app_name_end)
        {
            return 0;
        }
        // Iterate through bytes to parse application name and add into map entry
        for (index = 0; index < NAME_SIZE; index++)
        {
            if ((context->app_name_start + index) >= context->app_name_end)
            {
                break;
            }
            entry->name[index] = context->app_name_start[index];
        }
    }
    return 0;
}
