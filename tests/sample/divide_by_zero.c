// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Wall -c droppacket.c -o dropjit.o
//
// For bpf code: clang -target bpf -O2 -Wall -c droppacket.c -o droppacket.o
// this passes the checker

#include "ebpf.h"

#pragma clang section data = "maps"
ebpf_map_definition_t test_map = {.size = sizeof(ebpf_map_definition_t),
                                  .type = EBPF_MAP_TYPE_ARRAY,
                                  .key_size = sizeof(uint32_t),
                                  .value_size = sizeof(uint32_t),
                                  .max_entries = 1};

#pragma clang section text = "xdp"
uint32_t
divide_by_zero(xdp_md_t* ctx)
{
    uint32_t key = 0;
    uint32_t* value = ebpf_map_lookup_element(&test_map, &key);
    if (value) {
        return 100000 / *value;
    }
    return 0;
}
