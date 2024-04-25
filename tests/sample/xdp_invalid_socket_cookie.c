// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c xdp_invalid_socket_cookie.c -o xdp_invalid_socket_cookie.o
//
// For bpf code: clang -target bpf -O2 -Werror -c xdp_invalid_socket_cookie.c -o xdp_invalid_socket_cookie.o
//

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"

SEC("xdp")
int
xdp_invalid_socket_cookie(xdp_md_t* ctx)
{
    // Try to call the bpf_get_socket_cookie helper function.
    uint64_t socket_cookie = bpf_get_socket_cookie(ctx);

    bpf_printk("socket_cookie: %llx\n", socket_cookie);

Done:
    return XDP_PASS;
}