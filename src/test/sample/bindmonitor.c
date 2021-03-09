/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

// clang -O2 -Wall -c droppacket.c -o dropjit.o
// 
// For bpf code: clang -target bpf -O2 -Wall -c bindmonitor.c -o bindmonitor.o
// this passes the checker


#include "ebpf.h"

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

#pragma clang section data="maps"
bpf_map_def_t process_map = {
      .size        = sizeof(bpf_map_def_t),
      .type        = EBPF_MAP_TYPE_HASH,
      .key_size    = sizeof(uint64_t),
      .value_size  = sizeof(process_entry_t),
      .max_entries = 1024
};

bpf_map_def_t limits_map = {
      .size = sizeof(bpf_map_def_t),
      .type = EBPF_MAP_TYPE_ARRAY,
      .key_size = sizeof(uint32_t),
      .value_size = sizeof(uint32_t),
      .max_entries = 1
};

inline void copy_app_id(process_entry_t* entry, uint64_t start_index, char* begin, char* end)
{
    uint64_t index = 0;
    for (index = start_index; index < start_index + 16; index++)
    {
        entry->name[index] = (begin + index < end) ? begin[index] : 0;
    }
}

#pragma clang section text="bind"
int BindMonitor(bind_md_t* ctx)
{
    uint64_t key = ctx->process_id;
    uint32_t limit_key = 0;
    uint32_t* limit = ebpf_map_lookup_elem(&limits_map, &limit_key);
    if (!limit || *limit == 0)
    {
        return BIND_PERMIT;
    }

    process_entry_t* entry = ebpf_map_lookup_elem(&process_map, &key);
    if (!entry)
    {
        process_entry_t value = { 0 };
        // To work around a limitation in eBPF verifier, copy the string
        // in blocks of 16 bytes. Copying all 64 bytes triggers a verification
        // failure.
        copy_app_id(&value, 0, ctx->app_id_start, ctx->app_id_end);
        copy_app_id(&value, 16, ctx->app_id_start, ctx->app_id_end);
        copy_app_id(&value, 32, ctx->app_id_start, ctx->app_id_end);
        copy_app_id(&value, 48, ctx->app_id_start, ctx->app_id_end);
        ebpf_map_update_element(&process_map, &key, &value, 0);
        entry = ebpf_map_lookup_elem(&process_map, &key);
    }

    switch (ctx->operation)
    {
    case BIND_OPERATION_BIND:
        if (entry->count >= *limit)
        {
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

    return BIND_PERMIT;
}