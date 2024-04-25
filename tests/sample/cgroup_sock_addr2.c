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

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, destination_entry_key_t);
    __type(value, destination_entry_value_t);
    __uint(max_entries, 100);
} policy_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, sock_addr_audit_entry_t);
    __uint(max_entries, 100);
} audit_map SEC(".maps");

__inline void
update_audit_map_entry(bpf_sock_addr_t* ctx)
{
    uint64_t key = 0;
    sock_addr_audit_entry_t entry = {0};
    entry.process_id = bpf_sock_addr_get_current_pid_tgid(ctx);
    entry.logon_id = bpf_get_current_logon_id(ctx);
    entry.is_admin = bpf_is_current_admin(ctx);
    entry.local_port = ctx->msg_src_port;
    entry.socket_cookie = bpf_get_socket_cookie(ctx);

    key = entry.process_id;
    bpf_map_update_elem(&audit_map, &key, &entry, 0);
}

__inline int
redirect_v4(bpf_sock_addr_t* ctx)
{
    int verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    destination_entry_key_t entry = {0};
    char redirect_context[] = REDIRECT_CONTEXT_MESSAGE;

    if (((ctx->protocol != IPPROTO_TCP) && (ctx->protocol != IPPROTO_UDP)) || (ctx->family != AF_INET)) {
        return verdict;
    }

    entry.destination_ip.ipv4 = ctx->user_ip4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    // Find the entry in the policy map.
    destination_entry_value_t* policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL) {
        bpf_printk("Found v4 proxy entry value: %u, %u", policy->destination_ip.ipv4, policy->destination_port);

        // Currently, we are unable to validate the redirect context path for connected UDP.
        // Tracking issue #3052
        // When the above issue is resolved, we should validate setting the redirect_context unconditionally,
        // including when the verdict is BPF_SOCK_ADDR_VERDICT_REJECT.
        if (policy->connection_type != CONNECTED_UDP) {
            if (bpf_sock_addr_set_redirect_context(ctx, redirect_context, sizeof(redirect_context)) < 0) {
                return verdict;
            }
        }

        ctx->user_ip4 = policy->destination_ip.ipv4;
        ctx->user_port = policy->destination_port;

        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    update_audit_map_entry(ctx);

    return verdict;
}

__inline int
redirect_v6(bpf_sock_addr_t* ctx)
{
    int verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    destination_entry_key_t entry = {0};
    char redirect_context[] = REDIRECT_CONTEXT_MESSAGE;

    if (((ctx->protocol != IPPROTO_TCP) && (ctx->protocol != IPPROTO_UDP)) || (ctx->family != AF_INET6)) {
        return verdict;
    }

    // Copy the IPv6 address. Note this has a design flaw for scoped IPv6 addresses
    // where the scope id or interface is not provided, so the policy can match the
    // wrong address.
    __builtin_memcpy(entry.destination_ip.ipv6, ctx->user_ip6, sizeof(ctx->user_ip6));
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    // Find the entry in the policy map.
    destination_entry_value_t* policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL) {
        bpf_printk("Found v6 proxy entry value");

        // Currently, we are unable to validate the redirect context path for connected UDP.
        // Tracking issue #3052
        // When the above issue is resolved, we should validate setting the redirect_context unconditionally,
        // including when the verdict is BPF_SOCK_ADDR_VERDICT_REJECT.
        if (policy->connection_type != CONNECTED_UDP) {
            if (bpf_sock_addr_set_redirect_context(ctx, redirect_context, sizeof(redirect_context)) < 0) {
                return verdict;
            }
        }
        __builtin_memcpy(ctx->user_ip6, policy->destination_ip.ipv6, sizeof(ctx->user_ip6));
        ctx->user_port = policy->destination_port;

        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    update_audit_map_entry(ctx);

    return verdict;
}

SEC("cgroup/connect4")
int
connect_redirect4(bpf_sock_addr_t* ctx)
{
    return redirect_v4(ctx);
}

SEC("cgroup/connect6")
int
connect_redirect6(bpf_sock_addr_t* ctx)
{
    return redirect_v6(ctx);
}
