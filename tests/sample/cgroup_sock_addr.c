// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf.h"

typedef struct _ip_address
{
    union
    {
        uint32_t ipv4;
        uint32_t ipv6[4];
    };
} ip_address_t;

typedef struct _connection_tuple
{
    ip_address_t src_ip;
    uint16_t src_port;
    ip_address_t dst_ip;
    uint16_t dst_port;
    uint32_t protocol;
} connection_tuple_t;

SEC("maps")
struct bpf_map_def connection_policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(connection_tuple_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1};

__inline int
authorize_v4(bpf_sock_addr_t* ctx)
{
    connection_tuple_t tuple_key = {0};
    int* verdict = NULL;

    tuple_key.src_ip.ipv4 = ctx->msg_src_ip4;
    tuple_key.src_port = ctx->msg_src_port;
    tuple_key.dst_ip.ipv4 = ctx->user_ip4;
    tuple_key.dst_port = ctx->user_port;
    tuple_key.protocol = ctx->protocol;

    verdict = bpf_map_lookup_elem(&connection_policy_map, &tuple_key);

    return (verdict != NULL) ? *verdict : BPF_SOCK_ADDR_VERDICT_PROCEED;
}

__inline int
authorize_v6(bpf_sock_addr_t* ctx)
{
    connection_tuple_t tuple_key = {0};
    int* verdict;
    __builtin_memcpy(tuple_key.src_ip.ipv6, ctx->msg_src_ip6, sizeof(ctx->msg_src_ip6));
    tuple_key.src_port = ctx->msg_src_port;
    __builtin_memcpy(tuple_key.dst_ip.ipv6, ctx->user_ip6, sizeof(ctx->user_ip6));
    tuple_key.dst_port = ctx->user_port;
    tuple_key.protocol = ctx->protocol;

    verdict = bpf_map_lookup_elem(&connection_policy_map, &tuple_key);

    return (verdict != NULL) ? *verdict : BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("cgroup/connect4")
int
authorize_connect4(bpf_sock_addr_t* ctx)
{
    return authorize_v4(ctx);
}

SEC("cgroup/connect6")
int
authorize_connect6(bpf_sock_addr_t* ctx)
{
    return authorize_v6(ctx);
}

SEC("cgroup/recv_accept4")
int
authorize_recv_accept4(bpf_sock_addr_t* ctx)
{
    return authorize_v4(ctx);
}

SEC("cgroup/recv_accept6")
int
authorize_recv_accept6(bpf_sock_addr_t* ctx)
{
    return authorize_v6(ctx);
}