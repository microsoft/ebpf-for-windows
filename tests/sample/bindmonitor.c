/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

// clang -O2 -Wall -c droppacket.c -o dropjit.o
//
// For bpf code: clang -target bpf -O2 -Wall -c bindmonitor.c -o bindmonitor.o
// this passes the checker

#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

#pragma clang section data = "maps"
ebpf_map_definition_t process_map = {.size = sizeof(ebpf_map_definition_t),
                                     .type = EBPF_MAP_TYPE_HASH,
                                     .key_size = sizeof(uint64_t),
                                     .value_size = sizeof(process_entry_t),
                                     .max_entries = 1024};

ebpf_map_definition_t limits_map = {.size = sizeof(ebpf_map_definition_t),
                                    .type = EBPF_MAP_TYPE_ARRAY,
                                    .key_size = sizeof(uint32_t),
                                    .value_size = sizeof(uint32_t),
                                    .max_entries = 1};

inline process_entry_t*
find_or_create_process_entry(bind_md_t* ctx)
{
    uint64_t key = ctx->process_id;
    process_entry_t* entry;
    process_entry_t value = {0};
    int index;

    entry = ebpf_map_lookup_element(&process_map, &key);
    if (entry)
        return entry;

    if (ctx->operation != BIND_OPERATION_BIND)
        return entry;

    if (!ctx->app_id_start || !ctx->app_id_end)
        return entry;

    ebpf_map_update_element(&process_map, &key, &value, 0);
    entry = ebpf_map_lookup_element(&process_map, &key);
    if (!entry)
        return entry;

    for (index = 0; index < 64; index++) {
        if ((ctx->app_id_start + index) >= ctx->app_id_end)
            break;

        entry->name[index] = ctx->app_id_start[index];
    }
    return entry;
}

#pragma clang section text = "bind"
int
BindMonitor(bind_md_t* ctx)
{
    uint32_t limit_key = 0;
    process_entry_t* entry;
    uint32_t* limit = ebpf_map_lookup_element(&limits_map, &limit_key);
    if (!limit || *limit == 0)
        return BIND_PERMIT;

    entry = find_or_create_process_entry(ctx);

    if (!entry) {
        return BIND_PERMIT;
    }

    switch (ctx->operation) {
    case BIND_OPERATION_BIND:
        if (entry->count >= *limit) {
            return BIND_DENY;
        }

        entry->count++;
        break;
    case BIND_OPERATION_UNBIND:
        if (entry->count > 0)
            entry->count--;
        break;
    default:
        break;
    }

    if (entry->count == 0) {
        uint64_t key = ctx->process_id;
        ebpf_map_delete_element(&process_map, &key);
    }

    return BIND_PERMIT;
}
