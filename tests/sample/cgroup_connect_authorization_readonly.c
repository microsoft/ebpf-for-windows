// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "net/ip.h"
#include "socket_tests_common.h"

static __inline int
mutate_connect_authorization_context(bpf_sock_addr_t* ctx, uint32_t expected_family)
{
    if ((ctx->family != expected_family) || ((ctx->protocol != IPPROTO_TCP) && (ctx->protocol != IPPROTO_UDP))) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    // CONNECT_AUTHORIZATION treats the destination as read-only. The extension silently discards any
    // mutations to read-only fields and proceeds with the program's actual verdict.
    ctx->user_port ^= 1;
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

SEC("cgroup/connect_authorization4")
int
mutate_connect_authorization4(bpf_sock_addr_t* ctx)
{
    return mutate_connect_authorization_context(ctx, AF_INET);
}

SEC("cgroup/connect_authorization6")
int
mutate_connect_authorization6(bpf_sock_addr_t* ctx)
{
    return mutate_connect_authorization_context(ctx, AF_INET6);
}
