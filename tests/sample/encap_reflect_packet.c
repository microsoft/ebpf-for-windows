// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

#include "xdp_common.h"

inline int
encapsulate_ipv4_reflect_packet(xdp_md_t* ctx)
{
    int rc = XDP_DROP;

    // Adjust XDP context to allocate space for outer IPv4 header.
    if (bpf_xdp_adjust_head(ctx, (int)-sizeof(IPV4_HEADER)) < 0) {
        goto Done;
    }

    // The new ethernet header will be at the beginning of the expanded buffer.
    char* next_header = (char*)ctx->data;
    if (next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    ETHERNET_HEADER* new_ethernet_header = (ETHERNET_HEADER*)next_header;

    // The old ethernet header is at an offset sizeof(IPV4_HEADER) from the start of the XDP buffer.
    next_header = (char*)ctx->data;
    if (next_header + sizeof(IPV4_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    next_header = (char*)ctx->data + sizeof(IPV4_HEADER);
    ETHERNET_HEADER* old_ethernet_header = (ETHERNET_HEADER*)next_header;

    // The outer IPv4 header will be after the new ethernet header.
    next_header = (char*)(new_ethernet_header + 1);
    if (next_header + sizeof(IPV4_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    IPV4_HEADER* outer_ipv4_header = (IPV4_HEADER*)next_header;

    // The inner IPv4 header will be after the old ethernet header.
    next_header = (char*)(old_ethernet_header + 1);
    if (next_header + sizeof(IPV4_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    IPV4_HEADER* inner_ipv4_header = (IPV4_HEADER*)next_header;

    // Copy over the old ethernet header to the new one.
    __builtin_memcpy(new_ethernet_header, old_ethernet_header, sizeof(ETHERNET_HEADER));
    // Swap the MAC addresses.
    swap_mac_addresses(new_ethernet_header);

    // Swap the IP addresses for the inner IPv4 header.
    swap_ipv4_addresses(inner_ipv4_header);

    // Copy over the inner IP header to the outer IP header.
    __builtin_memcpy(outer_ipv4_header, inner_ipv4_header, sizeof(IPV4_HEADER));

    // Adjust header fields.
    outer_ipv4_header->Protocol = IPPROTO_IPV4;
    outer_ipv4_header->HeaderLength = sizeof(IPV4_HEADER) / sizeof(uint32_t);
    outer_ipv4_header->TotalLength = htons((ntohs(inner_ipv4_header->TotalLength) + sizeof(IPV4_HEADER)));
    // Compute the checksum of outer IPv4 header using bpf_csum_diff helper function.
    outer_ipv4_header->HeaderChecksum = 0;
    outer_ipv4_header->HeaderChecksum =
        (uint16_t)fold_csum(bpf_csum_diff(NULL, 0, outer_ipv4_header, sizeof(IPV4_HEADER), 0));

    rc = XDP_TX;

Done:
    return rc;
}

inline int
encapsulate_ipv6_reflect_packet(xdp_md_t* ctx)
{
    int rc = XDP_DROP;

    // Adjust XDP context to allocate space for outer IPv6 header.
    if (bpf_xdp_adjust_head(ctx, (int)-sizeof(IPV6_HEADER)) < 0) {
        goto Done;
    }

    // The new ethernet header will be at the beginning of the expanded buffer.
    char* next_header = (char*)ctx->data;
    if (next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    ETHERNET_HEADER* new_ethernet_header = (ETHERNET_HEADER*)next_header;

    // The old ethernet header is at an offset sizeof(IPV6_HEADER) from the start of the XDP buffer.
    next_header = (char*)ctx->data;
    if (next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    next_header = (char*)ctx->data + sizeof(IPV6_HEADER);
    ETHERNET_HEADER* old_ethernet_header = (ETHERNET_HEADER*)next_header;

    // The outer IPv6 header will be after the new ethernet header.
    next_header = (char*)(new_ethernet_header + 1);
    if (next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    IPV6_HEADER* outer_ipv6_header = (IPV6_HEADER*)next_header;

    // The inner IPv6 header will be after the old ethernet header.
    next_header = (char*)(old_ethernet_header + 1);
    if (next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    IPV6_HEADER* inner_ipv6_header = (IPV6_HEADER*)next_header;

    // Copy over the old ethernet header to the new one.
    __builtin_memcpy(new_ethernet_header, old_ethernet_header, sizeof(ETHERNET_HEADER));
    // Swap the MAC addresses.
    swap_mac_addresses(new_ethernet_header);

    // Swap the IP addresses for the inner IP header.
    swap_ipv6_addresses(inner_ipv6_header);

    // Copy over the inner IP header to the outer IP header.
    __builtin_memcpy(outer_ipv6_header, inner_ipv6_header, sizeof(IPV6_HEADER));

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
    if (next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    ethernet_header = (ETHERNET_HEADER*)next_header;
    next_header = (char*)(ethernet_header + 1);
    if (ethernet_header->Type == ntohs(ETHERNET_TYPE_IPV4)) {
        if (next_header + sizeof(IPV4_HEADER) > (char*)ctx->data_end) {
            goto Done;
        }
        // IPv4.
        IPV4_HEADER* ipv4_header = (IPV4_HEADER*)next_header;
        next_header = (char*)ipv4_header + sizeof(uint32_t) * ipv4_header->HeaderLength;
        if (ipv4_header->Protocol == IPPROTO_UDP) {
            if (next_header + sizeof(UDP_HEADER) > (char*)ctx->data_end) {
                goto Done;
            }
            // UDP.
            UDP_HEADER* udp_header = (UDP_HEADER*)next_header;
            if (udp_header->destPort == ntohs(REFLECTION_TEST_PORT)) {
                rc = encapsulate_ipv4_reflect_packet(ctx);
            }
        }
    } else if (ethernet_header->Type == ntohs(ETHERNET_TYPE_IPV6)) {
        if (next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end) {
            goto Done;
        }
        // IPv6.
        IPV6_HEADER* ipv6_header = (IPV6_HEADER*)next_header;
        next_header = (char*)(ipv6_header + 1);
        if (ipv6_header->NextHeader == IPPROTO_UDP) {
            if (next_header + sizeof(UDP_HEADER) > (char*)ctx->data_end) {
                goto Done;
            }
            // UDP.
            UDP_HEADER* udp_header = (UDP_HEADER*)next_header;
            if (udp_header->destPort == ntohs(REFLECTION_TEST_PORT)) {
                rc = encapsulate_ipv6_reflect_packet(ctx);
            }
        }
    }

Done:
    return rc;
}
