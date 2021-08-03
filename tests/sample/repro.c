/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

// clang -O2 -Wall -c droppacket.c -o dropjit.o
//
// For bpf code: clang -target bpf -O2 -Wall -c repro.c -o repro.o
// this passes the checker

#if defined(_MSC_VER)
typedef unsigned long long uint64_t;
#else
typedef unsigned long uint64_t;
#endif

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

#include "ebpf_helpers.h"

#pragma clang section data = "maps"
ebpf_map_definition_t test_map = {.size = sizeof(ebpf_map_definition_t),
                                  .type = BPF_MAP_TYPE_HASH,
                                  .key_size = sizeof(uint64_t),
                                  .value_size = sizeof(uint64_t),
                                  .max_entries = 1};

#pragma clang section text = "bind"
int
BindMonitor(bind_md_t* ctx)
{
    uint64_t key = ctx->process_id;

    uint64_t* value = bpf_map_lookup_elem(&test_map, &key);

    *value = 1;

    return BIND_PERMIT;
}
