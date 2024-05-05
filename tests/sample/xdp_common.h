// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"
#include "xdp_tests_common.h"

inline void
swap_mac_addresses(ETHERNET_HEADER* ethernet_header)
{
    mac_address_t mac = {0};
    __builtin_memcpy(mac, ethernet_header->Destination, sizeof(mac_address_t));
    __builtin_memcpy(ethernet_header->Destination, ethernet_header->Source, sizeof(mac_address_t));
    __builtin_memcpy(ethernet_header->Source, mac, sizeof(mac_address_t));
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
    __builtin_memcpy(address, ipv6_header->DestinationAddress, sizeof(ipv6_address_t));
    __builtin_memcpy(ipv6_header->DestinationAddress, ipv6_header->SourceAddress, sizeof(ipv6_address_t));
    __builtin_memcpy(ipv6_header->SourceAddress, address, sizeof(ipv6_address_t));
}

inline void
swap_ports(UDP_HEADER* udp_header)
{
    uint16_t src_port = udp_header->srcPort;
    udp_header->srcPort = udp_header->destPort;
    udp_header->destPort = src_port;
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
