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

#include "bpf_helpers.h"
#include "socket_tests_common.h"

#define REDIRECT_IP 16843009 // 1.1.1.1
#define PERMIT_IP 33620225   // Network byte order 1.1.1.2
#define BLOCK_IP 50397441    // Network byte order 1.1.1.3

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define AF_INET 2

SEC("maps")
struct bpf_map_def ingress_connection_policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(connection_tuple_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1};

SEC("maps")
struct bpf_map_def egress_connection_policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(connection_tuple_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1};

__inline int
authorize_v4(bpf_sock_addr_t* ctx)
{
    if (ctx->protocol != IPPROTO_TCP) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    if (ctx->family != AF_INET) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    if (ctx->user_ip4 == REDIRECT_IP) {
        ctx->user_port++;
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    if (ctx->user_ip4 == PERMIT_IP) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    return BPF_SOCK_ADDR_VERDICT_REJECT;
}

/*
__inline int
authorize_v6(bpf_sock_addr_t* ctx, struct bpf_map_def* connection_policy_map)
{
    connection_tuple_t tuple_key = {0};
    int* verdict;
    __builtin_memcpy(tuple_key.src_ip.ipv6, ctx->msg_src_ip6, sizeof(ctx->msg_src_ip6));
    tuple_key.src_port = ctx->msg_src_port;
    __builtin_memcpy(tuple_key.dst_ip.ipv6, ctx->user_ip6, sizeof(ctx->user_ip6));
    tuple_key.dst_port = ctx->user_port;
    tuple_key.protocol = ctx->protocol;
    tuple_key.interface_luid = ctx->interface_luid;

    verdict = bpf_map_lookup_elem(connection_policy_map, &tuple_key);

    return (verdict != NULL) ? *verdict : BPF_SOCK_ADDR_VERDICT_PROCEED;
}
*/

SEC("cgroup/connect4")
int
authorize_connect4(bpf_sock_addr_t* ctx)
{
    return authorize_v4(ctx);
}

/*
SEC("cgroup/connect6")
int
authorize_connect6(bpf_sock_addr_t* ctx)
{
    return authorize_v6(ctx, &egress_connection_policy_map);
}

SEC("cgroup/recv_accept4")
int
authorize_recv_accept4(bpf_sock_addr_t* ctx)
{
    return authorize_v4(ctx, &ingress_connection_policy_map);
}

SEC("cgroup/recv_accept6")
int
authorize_recv_accept6(bpf_sock_addr_t* ctx)
{
    return authorize_v6(ctx, &ingress_connection_policy_map);
}
*/