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

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define AF_INET 2
#define AF_INET6 0x17

SEC("maps")
struct bpf_map_def policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(destination_entry_t),
    .value_size = sizeof(destination_entry_t),
    .max_entries = 100};

__inline int
authorize_v4(bpf_sock_addr_t* ctx)
{
    int verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    destination_entry_t entry = {0};
    entry.destination_ip.ipv4 = ctx->user_ip4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP) {
        return verdict;
    }

    if (ctx->family != AF_INET) {
        return verdict;
    }

    // Find the entry in the policy map.
    destination_entry_t* policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL) {
        bpf_printk("Found v4 proxy entry value: %u, %u", policy->destination_ip.ipv4, policy->destination_port);
        ctx->user_ip4 = policy->destination_ip.ipv4;
        ctx->user_port = policy->destination_port;

        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    return verdict;
}

__inline int
authorize_v6(bpf_sock_addr_t* ctx)
{
    int verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    destination_entry_t entry = {0};

    if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP) {
        return verdict;
    }

    if (ctx->family != AF_INET6) {
        return verdict;
    }

    __builtin_memcpy(entry.destination_ip.ipv6, ctx->user_ip6, sizeof(ctx->user_ip6));
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    // Find the entry in the policy map.
    destination_entry_t* policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL) {
        bpf_printk("Found v6 proxy entry value");
        __builtin_memcpy(ctx->user_ip6, policy->destination_ip.ipv6, sizeof(ctx->user_ip6));
        ctx->user_port = policy->destination_port;

        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    return verdict;
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
