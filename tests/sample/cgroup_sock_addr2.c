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

SEC("maps")
struct bpf_map_def audit_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(sock_addr_audit_entry_t),
    .max_entries = 100};

__inline void
update_audit_map_entry(bpf_sock_addr_t* ctx)
{
    uint64_t key = 0;
    sock_addr_audit_entry_t entry = {0};
    entry.process_id = bpf_sock_addr_get_current_pid_tgid(ctx);
    entry.logon_id = bpf_get_current_logon_id(ctx);
    entry.is_admin = bpf_is_current_admin(ctx);
    entry.local_port = ctx->msg_src_port;

    key = entry.process_id;
    bpf_map_update_elem(&audit_map, &key, &entry, 0);
}

__inline int
redirect_v4(bpf_sock_addr_t* ctx)
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

    update_audit_map_entry(ctx);

    return verdict;
}

__inline int
redirect_v6(bpf_sock_addr_t* ctx)
{
    int verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    destination_entry_t entry = {0};

    if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP) {
        return verdict;
    }

    if (ctx->family != AF_INET6) {
        return verdict;
    }

    // Copy the IPv6 address. Note this has a design flaw for scoped IPv6 addresses
    // where the scope id or interface is not provided, so the policy can match the
    // wrong address.
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
