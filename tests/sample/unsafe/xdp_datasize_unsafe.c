// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c xdp_datasize_unsafe.c -o xdp_datasize_unsafe_jit.o
//
// For bpf code: clang -target bpf -O2 -Werror -c xdp_datsize_unsafe.c -o xdp_datasize_unsafe.o
//

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"

SEC("xdp")
inline void*
data_start(xdp_md_t* ctx)
{
    void* ptr;
    asm volatile("%0 = *(u32 *)(%1 + %2)" : "=r"(ptr) : "r"(ctx), "i"(__builtin_offsetof(xdp_md_t, data)));
    return ptr;
}

SEC("xdp")
int
unsafe_program(xdp_md_t* ctx)
{
    int rc = XDP_PASS;

    ETHERNET_HEADER* ethernet_header = NULL;
    char* next_header = data_start(ctx); // <== 64-bit truncated to 32-bit.
    if (next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }

    ethernet_header = (ETHERNET_HEADER*)next_header;
    next_header = (char*)(ethernet_header + 1);
    if (ethernet_header->Type != ntohs(ETHERNET_TYPE_IPV4) && ethernet_header->Type != ntohs(ETHERNET_TYPE_IPV6)) {
        rc = XDP_DROP;
    }

Done:
    return rc;
}
