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

SEC("maps")
ebpf_map_definition_in_file_t interface_index_map = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1};

SEC("xdp")
int
DropPacket(xdp_md_t* ctx)
{
    int rc = XDP_PASS;
    ETHERNET_HEADER* eth = NULL;
    long key = 0;

    uint32_t* interface_index = bpf_map_lookup_elem(&interface_index_map, &key);
    if (interface_index != NULL) {
        if (ctx->ingress_ifindex != *interface_index) {
            // Not interested in packets indicated over this interfce.
            goto Done;
        }
    }

    if ((char*)ctx->data + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) > (char*)ctx->data_end)
        goto Done;

    eth = (ETHERNET_HEADER*)ctx->data;
    if (ntohs(eth->Type) == 0x0800) {
        // IPv4.
        IPV4_HEADER* ipv4_header = (IPV4_HEADER*)(eth + 1);
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
