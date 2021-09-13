// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf.h"
#include "xdp_tests_common.h"

void
swap_mac_addresses(ETHERNET_HEADER* ethernet_header)
{
    mac_address_t mac = {0};
    memcpy(mac, ethernet_header->Destination, sizeof(mac_address_t));
    memcpy(ethernet_header->Destination, ethernet_header->Source, sizeof(mac_address_t));
    memcpy(ethernet_header->Source, mac, sizeof(mac_address_t));
}

void
swap_ipv4_addresses(IPV4_HEADER* ipv4_header)
{
    uint32_t address = ipv4_header->DestinationAddress;
    ipv4_header->DestinationAddress = ipv4_header->SourceAddress;
    ipv4_header->SourceAddress = address;
}

void
swap_ipv6_addresses(IPV6_HEADER* ipv6_header)
{
    ipv6_address_t address = {0};
    memcpy(address, ipv6_header->DestinationAddress, sizeof(ipv6_address_t));
    memcpy(ipv6_header->DestinationAddress, ipv6_header->SourceAddress, sizeof(ipv6_address_t));
    memcpy(ipv6_header->SourceAddress, address, sizeof(ipv6_address_t));
}

//
// This eBPF program intercepts inbound UDP packets destined to port REFLECTION_TEST_PORT and "reflects" it back
// by swapping the MAC and IP addresses. The program will only work for packets where UDP is the next header
// for IP header. For instance this will not work for AH packets.
//
SEC("xdp/reflect")
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

int
encapsulate_ipv4_reflect_packet(xdp_md_t* ctx)
{
    int rc = XDP_DROP;

    // Adjust XDP context to allocate space for outer IPv4 header.
    if (bpf_xdp_adjust_head(ctx, -sizeof(IPV4_HEADER)) < 0)
        goto Done;

    // The new ethernet header will be at the beginning of the expanded buffer.
    char* next_header = (char*)ctx->data;
    if ((char*)next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end)
        goto Done;
    ETHERNET_HEADER* new_ethernet_header = (ETHERNET_HEADER*)next_header;

    // The old ethernet header is at an offset sizeof(IPV4_HEADER) from the start of the XDP buffer.
    next_header = (char*)ctx->data;
    if ((char*)next_header + sizeof(IPV4_HEADER) > (char*)ctx->data_end)
        goto Done;
    next_header = (char*)ctx->data + sizeof(IPV4_HEADER);
    ETHERNET_HEADER* old_ethernet_header = (ETHERNET_HEADER*)next_header;

    // The outer IPv4 header will be after the new ethernet header.
    next_header = (char*)(new_ethernet_header + 1);
    if ((char*)next_header + sizeof(IPV4_HEADER) > (char*)ctx->data_end)
        goto Done;
    IPV4_HEADER* outer_ipv4_header = (IPV4_HEADER*)next_header;

    // The inner IPv4 header will be after the old ethernet header.
    next_header = (char*)(old_ethernet_header + 1);
    if ((char*)next_header + sizeof(IPV4_HEADER) > (char*)ctx->data_end)
        goto Done;
    IPV4_HEADER* inner_ipv4_header = (IPV4_HEADER*)next_header;

    // Copy over the old ethernet header to the new one.
    memcpy(new_ethernet_header, old_ethernet_header, sizeof(ETHERNET_HEADER));
    // Swap the MAC addresses.
    swap_mac_addresses(new_ethernet_header);

    // Copy over the inner IP header to the encap IP header.
    memcpy(outer_ipv4_header, inner_ipv4_header, sizeof(IPV4_HEADER));
    // Swap the IP addresses.
    swap_ipv4_addresses(outer_ipv4_header);
    // Adjust header fields.
    outer_ipv4_header->Protocol = IPPROTO_IPV4;
    outer_ipv4_header->HeaderLength = sizeof(IPV4_HEADER) / sizeof(uint32_t);
    outer_ipv4_header->TotalLength = htons((ntohs(inner_ipv4_header->TotalLength) + sizeof(IPV4_HEADER)));
    outer_ipv4_header->HeaderChecksum = 0;

    rc = XDP_TX;

Done:
    return rc;
}

int
encapsulate_ipv6_reflect_packet(xdp_md_t* ctx)
{
    int rc = XDP_DROP;

    // Adjust XDP context to allocate space for outer IPv6 header.
    if (bpf_xdp_adjust_head(ctx, -sizeof(IPV6_HEADER)) < 0)
        goto Done;

    // The new ethernet header will be at the beginning of the expanded buffer.
    char* next_header = (char*)ctx->data;
    if ((char*)next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end)
        goto Done;
    ETHERNET_HEADER* new_ethernet_header = (ETHERNET_HEADER*)next_header;

    // The old ethernet header is at an offset sizeof(IPV6_HEADER) from the start of the XDP buffer.
    next_header = (char*)ctx->data;
    if ((char*)next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end)
        goto Done;
    next_header = (char*)ctx->data + sizeof(IPV6_HEADER);
    ETHERNET_HEADER* old_ethernet_header = (ETHERNET_HEADER*)next_header;

    // The outer IPv6 header will be after the new ethernet header.
    next_header = (char*)(new_ethernet_header + 1);
    if ((char*)next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end)
        goto Done;
    IPV6_HEADER* outer_ipv6_header = (IPV6_HEADER*)next_header;

    // The inner IPv6 header will be after the old ethernet header.
    next_header = (char*)(old_ethernet_header + 1);
    if ((char*)next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end)
        goto Done;
    IPV6_HEADER* inner_ipv6_header = (IPV6_HEADER*)next_header;

    // Copy over the old ethernet header to the new one.
    memcpy(new_ethernet_header, old_ethernet_header, sizeof(ETHERNET_HEADER));
    // Swap the MAC addresses.
    swap_mac_addresses(new_ethernet_header);

    // Copy over the inner IP header to the encap IP header.
    memcpy(outer_ipv6_header, inner_ipv6_header, sizeof(IPV6_HEADER));
    // Swap the IP addresses.
    swap_ipv6_addresses(outer_ipv6_header);
    // Adjust header fields.
    outer_ipv6_header->NextHeader = IPPROTO_IPV6;
    outer_ipv6_header->PayloadLength = htons((ntohs(inner_ipv6_header->PayloadLength) + sizeof(IPV6_HEADER)));

    rc = XDP_TX;

Done:
    return rc;
}

//
// Same as the reflect_packet function, except the reflected packet is encapsulated in a new IP header.
// The addresses on the outer IP header are the reverse of those on the inner IP header.
// This program uses the bpf_xdp_adjust_head helper function.
// (This program can only perform v4 in v4 and v6 in v6 encapsulation.)
//
SEC("xdp/encap_reflect")
int
encap_reflect_packet(xdp_md_t* ctx)
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
            if (udp_header->destPort == ntohs(REFLECTION_TEST_PORT))
                rc = encapsulate_ipv4_reflect_packet(ctx);
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
            if (udp_header->destPort == ntohs(REFLECTION_TEST_PORT))
                rc = encapsulate_ipv6_reflect_packet(ctx);
        }
    }

Done:
    return rc;
}