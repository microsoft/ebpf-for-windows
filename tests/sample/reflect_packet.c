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
swap_mac_addresses(ETHERNET_HEADER* eth_hdr)
{
    mac_address_t temp = {0};
    copy_mac_address(temp, eth_hdr->Destination);
    copy_mac_address(eth_hdr->Destination, eth_hdr->Source);
    copy_mac_address(eth_hdr->Source, temp);
}

void
swap_ipv4_addresses(IPV4_HEADER* ipv4_hdr)
{
    uint32_t temp = ipv4_hdr->DestinationAddress;
    ipv4_hdr->DestinationAddress = ipv4_hdr->SourceAddress;
    ipv4_hdr->SourceAddress = temp;
}

void
copy_ipv6_address(ipv6_address_t destination, ipv6_address_t source)
{
    for (int i = 0; i < sizeof(ipv6_address_t); i++)
        destination[i] = source[i];
}

void
swap_ipv6_addresses(IPV6_HEADER* ipv6_hdr)
{
    ipv6_address_t temp = {0};
    copy_ipv6_address(temp, ipv6_hdr->DestinationAddress);
    copy_ipv6_address(ipv6_hdr->DestinationAddress, ipv6_hdr->SourceAddress);
    copy_ipv6_address(ipv6_hdr->SourceAddress, temp);
}

//
// This eBPF program intercepts inbound UDP packets destined to port REFLECTION_TEST_PORT and "reflects" it back
// by swapping the MAC and IP addresses.
//
SEC("xdp")
int
reflect_packet(xdp_md_t* ctx)
{
    int rc = XDP_PASS;

    ETHERNET_HEADER* eth_hdr = NULL;
    char* next_header = (char*)ctx->data;
    if ((char*)next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end)
        goto Done;
    eth_hdr = (ETHERNET_HEADER*)next_header;
    next_header = (char*)(eth_hdr + 1);
    if (eth_hdr->Type == ntohs(ETHERNET_TYPE_IPV4)) {
        if ((char*)next_header + sizeof(IPV4_HEADER) > (char*)ctx->data_end)
            goto Done;
        // IPv4.
        IPV4_HEADER* ipv4_hdr = (IPV4_HEADER*)next_header;
        next_header = (char*)(ipv4_hdr + 1);
        if (ipv4_hdr->Protocol == 17) {
            if ((char*)next_header + sizeof(UDP_HEADER) > (char*)ctx->data_end)
                goto Done;
            // UDP.
            UDP_HEADER* udphdr = (UDP_HEADER*)next_header;
            if (udphdr->destPort == ntohs(REFLECTION_TEST_PORT)) {
                swap_mac_addresses(eth_hdr);
                swap_ipv4_addresses(ipv4_hdr);
                rc = XDP_TX;
                goto Done;
            }
        }
    } else if (eth_hdr->Type == ntohs(ETHERNET_TYPE_IPV6)) {
        if ((char*)next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end)
            goto Done;
        // IPv4.
        IPV6_HEADER* ipv6_hdr = (IPV6_HEADER*)next_header;
        next_header = (char*)(ipv6_hdr + 1);
        if (ipv6_hdr->NextHeader == 17) {
            if ((char*)next_header + sizeof(UDP_HEADER) > (char*)ctx->data_end)
                goto Done;
            // UDP.
            UDP_HEADER* udphdr = (UDP_HEADER*)next_header;
            if (udphdr->destPort == ntohs(REFLECTION_TEST_PORT)) {
                swap_mac_addresses(eth_hdr);
                swap_ipv6_addresses(ipv6_hdr);
                rc = XDP_TX;
                goto Done;
            }
        }
    }

Done:
    return rc;
}