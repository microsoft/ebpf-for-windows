/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

// clang -O2 -Wall -c droppacket.c -o dropjit.o
// 
// For bpf code: clang -target bpf -O2 -Wall -c bindmonitor.c -o bindmonitor.o
// this passes the checker


#include "ebpf.h"

#pragma clang section data="maps"
bpf_map_def_t process_map = {
      .size        = sizeof(bpf_map_def_t),
      .type        = EBPF_MAP_TYPE_HASH,
      .key_size    = sizeof(__u64),
      .value_size  = sizeof(__u32),
      .max_entries = 1024
};

#pragma clang section text="bind"
int BindMonitor(bind_md_t* ctx)
{
    long key = ctx->process_id;
    __u32* count = ebpf_map_lookup_elem(&process_map, &key);

    if (!count)
    {
        long value = 0;
        ebpf_map_update_element(&process_map, &value, &key, 0);
        count = ebpf_map_lookup_elem(&process_map, &key);
    }

    if (count)
        switch (ctx->operation)
        {
        case BIND_OPERATION_BIND:
            *count = (*count) + 1;
        case BIND_OPERATION_UNBIND:
            *count = (*count) - 1;
        default:
            break;
        }

    return BIND_PERMIT;
}