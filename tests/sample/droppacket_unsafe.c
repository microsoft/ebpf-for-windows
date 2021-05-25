// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Wall -c droppacket.c -o dropjit.o
//
// For bpf code: clang -target bpf -O2 -Wall -c droppacket.c -o droppacket.o
// this passes the checker

#include "ebpf.h"

#pragma clang section data = "maps"
ebpf_map_definition_t port_map = {.size = sizeof(ebpf_map_definition_t),
                                  .type = EBPF_MAP_TYPE_ARRAY,
                                  .key_size = sizeof(uint32_t),
                                  .value_size = sizeof(uint64_t),
                                  .max_entries = 1};

#pragma clang section text = "xdp"
int
DropPacket(xdp_md_t* ctx)
{
    IPV4_HEADER* iphdr = (IPV4_HEADER*)ctx->data;
    UDP_HEADER* udphdr = (UDP_HEADER*)(iphdr + 1);
    int rc = XDP_PASS;

    // udp
    if (iphdr->Protocol == 17) {
        if (ntohs(udphdr->length) <= sizeof(UDP_HEADER)) {
            long key = 0;
            long* count = ebpf_map_lookup_element(&port_map, &key);
            if (count)
                *count = (*count + 1);
            rc = XDP_DROP;
        }
    }
    return rc;
}
