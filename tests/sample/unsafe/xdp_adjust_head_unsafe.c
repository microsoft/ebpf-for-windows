// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c xdp_adjust_head_unsafe.c -o xdp_adjust_head_unsafe_jit.o
//
// For bpf code: clang -target bpf -O2 -Werror -c xdp_adjust_head_unsafe.c -o xdp_adjust_head_unsafe.o
//

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"

SEC("xdp/xdp_adjust_head_unsafe")
int
xdp_adjust_head_unsafe(xdp_md_t* ctx)
{
    int rc = XDP_PASS;

    ETHERNET_HEADER* ethernet_header = NULL;
    char* next_header = (char*)ctx->data;
    if (next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }

    // Adjust the head of the packet
    if (bpf_xdp_adjust_head(ctx, sizeof(ETHERNET_HEADER) < 0)) {
        rc = XDP_DROP;
        goto Done;
    }

    // Access the packet without checking for safety.
    next_header = (char*)ctx->data + sizeof(ETHERNET_HEADER);
    ethernet_header = (ETHERNET_HEADER*)next_header;

    // Access the Ethernet header fields.
    ethernet_header->Type = 0x0800;
Done:
    return rc;
}
