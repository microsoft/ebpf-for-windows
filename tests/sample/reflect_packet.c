// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf.h"
#include "xdp_tests_common.h"

void
copy_mac_address(uint8_t destination[6], uint8_t source[6])
{
    for (int i = 0; i < 6; i++)
        destination[i] = source[i];
}

void
swap_mac_addresses(ETHERNET_HEADER* eth_hdr)
{
    uint8_t temp[6] = {0};
    copy_mac_address(temp, eth_hdr->Destination);
    copy_mac_address(eth_hdr->Destination, eth_hdr->Source);
    copy_mac_address(eth_hdr->Source, temp);
}

void
swap_ip_addresses(IPV4_HEADER* iphdr)
{
    uint32_t temp = iphdr->DestinationAddress;
    iphdr->DestinationAddress = iphdr->SourceAddress;
    iphdr->SourceAddress = temp;
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
    if ((char*)ctx->data + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) > (char*)ctx->data_end)
        goto Done;
    eth_hdr = (ETHERNET_HEADER*)ctx->data;
    if (ntohs(eth_hdr->Type) == 0x800) {
        // IPv4.
        IPV4_HEADER* iphdr = (IPV4_HEADER*)(eth_hdr + 1);
        if (iphdr->Protocol == 17) {
            // UDP.
            UDP_HEADER* udphdr = (UDP_HEADER*)(iphdr + 1);
            if (udphdr->destPort == ntohs(REFLECTION_TEST_PORT)) {
                swap_mac_addresses(eth_hdr);
                swap_ip_addresses(iphdr);
                rc = XDP_TX;
                goto Done;
            }
        }
    }
Done:
    return rc;
}