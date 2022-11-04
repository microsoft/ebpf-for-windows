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
authorize_v4(bpf_sock_addr_t* ctx, struct bpf_map_def* connection_policy_map)
{
    connection_tuple_t tuple_key = {0};
    int* verdict = NULL;

    tuple_key.dst_ip.ipv4 = ctx->user_ip4;
    tuple_key.dst_port = ctx->user_port;
    tuple_key.protocol = ctx->protocol;

    verdict = bpf_map_lookup_elem(connection_policy_map, &tuple_key);

    return (verdict != NULL) ? *verdict : BPF_SOCK_ADDR_VERDICT_PROCEED;
}

__inline int
authorize_v6(bpf_sock_addr_t* ctx, struct bpf_map_def* connection_policy_map)
{
    connection_tuple_t tuple_key = {0};
    int* verdict;
    __builtin_memcpy(tuple_key.dst_ip.ipv6, ctx->user_ip6, sizeof(ctx->user_ip6));
    tuple_key.dst_port = ctx->user_port;
    tuple_key.protocol = ctx->protocol;

    verdict = bpf_map_lookup_elem(connection_policy_map, &tuple_key);

    return (verdict != NULL) ? *verdict : BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("cgroup/connect4")
int
authorize_connect4(bpf_sock_addr_t* ctx)
{
    return authorize_v4(ctx, &egress_connection_policy_map);
}

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
