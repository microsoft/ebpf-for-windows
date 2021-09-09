// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf.h"
#include "xdp_tests_common.h"

void
copy_mac_address(mac_address_t destination, mac_address_t source)
{
    for (int i = 0; i < sizeof(mac_address_t); i++)
        destination[i] = source[i];
}

void
swap_mac_addresses(ETHERNET_HEADER* ethernet_header)
{
    mac_address_t mac = {0};
    copy_mac_address(mac, ethernet_header->Destination);
    copy_mac_address(ethernet_header->Destination, ethernet_header->Source);
    copy_mac_address(ethernet_header->Source, mac);
}

void
swap_ipv4_addresses(IPV4_HEADER* ipv4_header)
{
    uint32_t address = ipv4_header->DestinationAddress;
    ipv4_header->DestinationAddress = ipv4_header->SourceAddress;
    ipv4_header->SourceAddress = address;
}

void
copy_ipv6_address(ipv6_address_t destination, ipv6_address_t source)
{
    for (int i = 0; i < sizeof(ipv6_address_t); i++)
        destination[i] = source[i];
}

void
swap_ipv6_addresses(IPV6_HEADER* ipv6_header)
{
    ipv6_address_t address = {0};
    copy_ipv6_address(address, ipv6_header->DestinationAddress);
    copy_ipv6_address(ipv6_header->DestinationAddress, ipv6_header->SourceAddress);
    copy_ipv6_address(ipv6_header->SourceAddress, address);
}

//
// This eBPF program intercepts inbound UDP packets destined to port REFLECTION_TEST_PORT and "reflects" it back
// by swapping the MAC and IP addresses. The program will only work for packets where UDP is the next header
// for IP header. For instance this will not work for AH packets.
//
SEC("xdp")
int
reflect_packet(xdp_md_t* ctx)
{
    int rc = XDP_PASS;

    ETHERNET_HEADER* ethernet_header = NULL;
    char* next_header = (char*)ctx->data;
    if ((char*)next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end)
        goto Done;
    ethernet_header = (ETHERNET_HEADER*)next_header;
    next_header = (char*)(ethernet_header + 1);
    if (ethernet_header->Type == ntohs(ETHERNET_TYPE_IPV4)) {
        if ((char*)next_header + sizeof(IPV4_HEADER) > (char*)ctx->data_end)
            goto Done;
        // IPv4.
        IPV4_HEADER* ipv4_header = (IPV4_HEADER*)next_header;
        next_header = (char*)ipv4_header + sizeof(uint32_t) * ipv4_header->HeaderLength;
        if (ipv4_header->Protocol == IPPROTO_UDP) {
            if ((char*)next_header + sizeof(UDP_HEADER) > (char*)ctx->data_end)
                goto Done;
            // UDP.
            UDP_HEADER* udp_header = (UDP_HEADER*)next_header;
            if (udp_header->destPort == ntohs(REFLECTION_TEST_PORT)) {
                swap_mac_addresses(ethernet_header);
                swap_ipv4_addresses(ipv4_header);
                rc = XDP_TX;
                goto Done;
            }
        }
    } else if (ethernet_header->Type == ntohs(ETHERNET_TYPE_IPV6)) {
        if ((char*)next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end)
            goto Done;
        // IPv6.
        IPV6_HEADER* ipv6_header = (IPV6_HEADER*)next_header;
        next_header = (char*)(ipv6_header + 1);
        if (ipv6_header->NextHeader == IPPROTO_UDP) {
            if ((char*)next_header + sizeof(UDP_HEADER) > (char*)ctx->data_end)
                goto Done;
            // UDP.
            UDP_HEADER* udp_header = (UDP_HEADER*)next_header;
            if (udp_header->destPort == ntohs(REFLECTION_TEST_PORT)) {
                swap_mac_addresses(ethernet_header);
                swap_ipv6_addresses(ipv6_header);
                rc = XDP_TX;
                goto Done;
            }
        }
    }

Done:
    return rc;
}