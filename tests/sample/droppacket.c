// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c droppacket.c -o dropjit.o
//
// For bpf code: clang -target bpf -O2 -Werror -c droppacket.c -o droppacket.o
// this passes the checker

#include "bpf_helpers.h"
#include "ebpf.h"

SEC("maps")
ebpf_map_definition_in_file_t dropped_packet_map = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 1};

SEC("xdp")
int
DropPacket(xdp_md_t* ctx)
{
    int rc = XDP_PASS;
    ETHERNET_HEADER* ethernet_header = NULL;
    long key = 0;

    if ((char*)ctx->data + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) > (char*)ctx->data_end)
        goto Done;

    ethernet_header = (ETHERNET_HEADER*)ctx->data;
    if (ntohs(ethernet_header->Type) == 0x0800) {
        // IPv4.
        IPV4_HEADER* ipv4_header = (IPV4_HEADER*)(ethernet_header + 1);
        if (ipv4_header->Protocol == IPPROTO_UDP) {
            // UDP.
            char* next_header = (char*)ipv4_header + sizeof(uint32_t) * ipv4_header->HeaderLength;
            if ((char*)next_header + sizeof(UDP_HEADER) > (char*)ctx->data_end)
                goto Done;
            UDP_HEADER* udp_header = (UDP_HEADER*)((char*)ipv4_header + sizeof(uint32_t) * ipv4_header->HeaderLength);
            if (ntohs(udp_header->length) <= sizeof(UDP_HEADER)) {
                long* count = bpf_map_lookup_elem(&dropped_packet_map, &key);
                if (count)
                    *count = (*count + 1);
                rc = XDP_DROP;
            }
        }
    }
Done:
    return rc;
}
