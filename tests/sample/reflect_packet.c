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
                swap_mac_addresses(ethernet_header);
                swap_ipv4_addresses(ipv4_header);
                rc = XDP_TX;
                goto Done;
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