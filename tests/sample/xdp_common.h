// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf.h"
#include "xdp_tests_common.h"

inline void
swap_mac_addresses(ETHERNET_HEADER* ethernet_header)
{
    mac_address_t mac = {0};
    memcpy(mac, ethernet_header->Destination, sizeof(mac_address_t));
    memcpy(ethernet_header->Destination, ethernet_header->Source, sizeof(mac_address_t));
    memcpy(ethernet_header->Source, mac, sizeof(mac_address_t));
}

inline void
swap_ipv4_addresses(IPV4_HEADER* ipv4_header)
{
    uint32_t address = ipv4_header->DestinationAddress;
    ipv4_header->DestinationAddress = ipv4_header->SourceAddress;
    ipv4_header->SourceAddress = address;
}

inline void
swap_ipv6_addresses(IPV6_HEADER* ipv6_header)
{
    ipv6_address_t address = {0};
    memcpy(address, ipv6_header->DestinationAddress, sizeof(ipv6_address_t));
    memcpy(ipv6_header->DestinationAddress, ipv6_header->SourceAddress, sizeof(ipv6_address_t));
    memcpy(ipv6_header->SourceAddress, address, sizeof(ipv6_address_t));
}

inline int
fold_csum(int csum)
{
    int folded_csum = csum;
    folded_csum = (folded_csum >> 16) + (folded_csum & 0xFFFF);
    folded_csum = (folded_csum >> 16) + (folded_csum & 0xFFFF);
    folded_csum = (uint16_t)~folded_csum;
    return folded_csum;
}