// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdbool.h>
#include <stdint.h>
#include "ebpf_helpers.h"
#include "ebpf.h"

#define NO_FLAGS 0

#pragma clang section data = "maps"
ebpf_map_definition_t byte_map = {
    .size = sizeof(ebpf_map_definition_t), .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(five_tuple_t), .value_size = sizeof(uint64_t), .max_entries = 500};

inline five_tuple_t
parse_five_tuple(mac_md_t* context)
{
    five_tuple_t five_tuple = {0};
    if (context->v4)
    {
        IPV4_HEADER* iphdr = (IPV4_HEADER*)context->data;
        if ((char*)context->data + sizeof(IPV4_HEADER) > (char*)context->data_end) {
            return five_tuple;
        }

        //Get Protocol and Header
        if ((char*)context->data + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) <= (char*)context->data_end
            && iphdr->Protocol == 17) { // UDP
                five_tuple.protocol = 0x11;
                UDP_HEADER* udphdr = (UDP_HEADER*)(iphdr + 1);
                five_tuple.source_port = udphdr->srcPort;
                five_tuple.dest_port = udphdr->destPort;
        }
        else if ((char*)context->data + sizeof(IPV4_HEADER) + sizeof(TCP_HEADER) <= (char*)context->data_end
            && iphdr->Protocol == 6){ // TCP
                five_tuple.protocol = 0x06;
                TCP_HEADER* tcphdr = (TCP_HEADER*)(iphdr + 1);
                five_tuple.source_port = tcphdr->srcPort;
                five_tuple.dest_port = tcphdr->destPort;
        }
        else { // Other Protocol
            five_tuple.protocol = iphdr->Protocol;
            return five_tuple;
        }
        *(uint32_t *)five_tuple.source_ip = iphdr->SourceAddress;
        *(uint32_t *)five_tuple.dest_ip = iphdr->DestinationAddress;
        five_tuple.v4 = true;
    }
    else {
        int index;
        IPV6_HEADER* iphdr = (IPV6_HEADER*)context->data;
        if ((char*)context->data + sizeof(IPV6_HEADER) > (char*)context->data_end) {
            return five_tuple;
        }

        //Get Protocol and Header
        if ((char*)context->data + sizeof(IPV6_HEADER) + sizeof(UDP_HEADER) <= (char*)context->data_end
            && iphdr->NextHeader == 17) { // UDP
                five_tuple.protocol = 0x11;
                UDP_HEADER* udphdr = (UDP_HEADER*)(iphdr + 1);
                five_tuple.source_port = udphdr->srcPort;
                five_tuple.dest_port = udphdr->destPort;
        }
        else if ((char*)context->data + sizeof(IPV6_HEADER) + sizeof(TCP_HEADER) <= (char*)context->data_end
            && iphdr->NextHeader == 6){ // TCP
                five_tuple.protocol = 0x06;
                TCP_HEADER* tcphdr = (TCP_HEADER*)(iphdr + 1);
                five_tuple.source_port = tcphdr->srcPort;
                five_tuple.dest_port = tcphdr->destPort;
        }
        else {
            five_tuple.protocol = iphdr->NextHeader;
            return five_tuple;
        }
        for (index = 0; index < 16; index++) {
            five_tuple.source_ip[index] =
                (uint8_t)iphdr->SourceAddress.u.Byte[index];
            five_tuple.dest_ip[index] =
                (uint8_t)iphdr->DestinationAddress.u.Byte[index];
        }
        five_tuple.v4 = false;
    }
    return five_tuple;
}

mac_hook_t CountBytes;

#pragma clang section text = "mac"
int CountBytes(mac_md_t* context)
{
    five_tuple_t key = parse_five_tuple(context);
    uint64_t value = context->packet_length;
    uint64_t* byte_count = bpf_map_lookup_elem(&byte_map, &key);

    if (!byte_count)
    {
        bpf_map_update_elem(&byte_map, &key, &value, NO_FLAGS);
    }
    else
    {
        value = *byte_count + value;
        bpf_map_update_elem(&byte_map, &key, &value, NO_FLAGS);
    }
    return 0;
}