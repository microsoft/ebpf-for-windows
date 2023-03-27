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
decapsulate_ipv4_reflect_packet(xdp_md_t* ctx)
{
    int rc = XDP_DROP;

    // The old ethernet header will be at the beginning of the buffer.
    ETHERNET_HEADER* old_ethernet_header = (ETHERNET_HEADER*)ctx->data;

    // Find the length of the outer IPv4 header.
    IPV4_HEADER* ipv4_header = (IPV4_HEADER*)(old_ethernet_header + 1);
    uint64_t outer_ipv4_length = sizeof(uint32_t) * ipv4_header->HeaderLength;
    // The new position of the ethernet header after de-capsulation of the outer IP header would be at an offset
    // outer_ipv4_length from the beginning of the buffer.
    if ((char*)ctx->data + outer_ipv4_length > (char*)ctx->data_end) {
        goto Done;
    }
    char* new_ethernet_header = (char*)ctx->data + outer_ipv4_length;

    // Copy over the old ethernet header to the new one.
    if (new_ethernet_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    __builtin_memcpy(new_ethernet_header, old_ethernet_header, sizeof(ETHERNET_HEADER));

    // Adjust XDP context to free space for outer IPv4 header.
    if (bpf_xdp_adjust_head(ctx, sizeof(IPV4_HEADER)) < 0) {
        goto Done;
    }

    rc = XDP_PASS;

Done:
    return rc;
}

inline int
decapsulate_ipv6_reflect_packet(xdp_md_t* ctx)
{
    int rc = XDP_DROP;

    // The old ethernet header will be at the beginning of the buffer.
    ETHERNET_HEADER* old_ethernet_header = (ETHERNET_HEADER*)ctx->data;

    // The new position of the ethernet header  after de-capsulation of the outer IP header would be at an offset
    // sizeof(IPV6_HEADER) from the beginning of the buffer.
    char* new_ethernet_header = (char*)ctx->data + sizeof(IPV6_HEADER);

    // Copy over the old ethernet header to the new one.
    if (new_ethernet_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }
    __builtin_memcpy(new_ethernet_header, old_ethernet_header, sizeof(ETHERNET_HEADER));

    // Adjust XDP context to free space for outer IPv6 header.
    if (bpf_xdp_adjust_head(ctx, sizeof(IPV6_HEADER)) < 0) {
        goto Done;
    }

    rc = XDP_PASS;

Done:
    return rc;
}

//
// This program performs de-capsulation of the outer IP header of IP-in-IP packets.
// This program uses the bpf_xdp_adjust_head helper function.
// (This program can only perform de-capsulation for v4 in v4 and v6 in v6 packets.)
// (This program assumes Ethernet II frames.)
//
SEC("xdp/decapsulate_reflect")
int
decapsulate_permit_packet(xdp_md_t* ctx)
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
        if (ipv4_header->Protocol == IPPROTO_IPV4) {
            if ((char*)next_header + sizeof(IPV4_HEADER) > (char*)ctx->data_end) {
                goto Done;
            }
            // IPv4 in IPv4.
            rc = decapsulate_ipv4_reflect_packet(ctx);
        }
    } else if (ethernet_header->Type == ntohs(ETHERNET_TYPE_IPV6)) {
        if (next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end) {
            goto Done;
        }
        // IPv6.
        IPV6_HEADER* ipv6_header = (IPV6_HEADER*)next_header;
        next_header = (char*)(ipv6_header + 1);
        if (ipv6_header->NextHeader == IPPROTO_IPV6) {
            if (next_header + sizeof(IPV6_HEADER) > (char*)ctx->data_end) {
                goto Done;
            }
            // IPv6 in IPv6.
            rc = decapsulate_ipv6_reflect_packet(ctx);
        }
    }

Done:
    return rc;
}
