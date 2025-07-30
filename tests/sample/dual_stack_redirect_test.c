// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// This is a simple test program to demonstrate the dual stack redirect scenario
// that was fixed in PR #2562. It shows how a dual stack socket connecting to 
// an IPv4-mapped address would trigger the v6 connect redirect filter, and then
// when the proxy makes an IPv4 connection, it should be recognized as REDIRECTED_BY_SELF.

#include "bpf_helpers.h"
#include "socket_tests_common.h"

#define IPPROTO_TCP 6
#define AF_INET 2
#define AF_INET6 0x17

// Test map to control redirect behavior
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, destination_entry_key_t);
    __type(value, destination_entry_value_t);
    __uint(max_entries, 100);
} dual_stack_test_policy_map SEC(".maps");

// Map to track connection attempts for testing
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 10);
} dual_stack_test_counter_map SEC(".maps");

__inline void
increment_counter(uint32_t counter_id)
{
    uint64_t* count = bpf_map_lookup_elem(&dual_stack_test_counter_map, &counter_id);
    if (count != NULL) {
        (*count)++;
    } else {
        uint64_t initial_count = 1;
        bpf_map_update_elem(&dual_stack_test_counter_map, &counter_id, &initial_count, 0);
    }
}

__inline int
dual_stack_redirect_v4(bpf_sock_addr_t* ctx)
{
    int verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    destination_entry_key_t entry = {0};
    char redirect_context[] = REDIRECT_CONTEXT_MESSAGE;

    if ((ctx->protocol != IPPROTO_TCP) || (ctx->family != AF_INET)) {
        return verdict;
    }

    // Increment counter for IPv4 connect attempts
    uint32_t counter_id = 0; // IPv4 connect counter
    increment_counter(counter_id);

    entry.destination_ip.ipv4 = ctx->user_ip4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    // Find the entry in the policy map.
    destination_entry_value_t* policy = bpf_map_lookup_elem(&dual_stack_test_policy_map, &entry);
    if (policy != NULL) {
        bpf_printk("Dual stack test: IPv4 redirect to proxy");
        
        if (bpf_sock_addr_set_redirect_context(ctx, redirect_context, sizeof(redirect_context)) < 0) {
            return verdict;
        }

        ctx->user_ip4 = policy->destination_ip.ipv4;
        ctx->user_port = policy->destination_port;

        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    return verdict;
}

__inline int
dual_stack_redirect_v6(bpf_sock_addr_t* ctx)
{
    int verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    destination_entry_key_t entry = {0};
    char redirect_context[] = REDIRECT_CONTEXT_MESSAGE;

    if ((ctx->protocol != IPPROTO_TCP) || (ctx->family != AF_INET6)) {
        return verdict;
    }

    // Increment counter for IPv6 connect attempts (including dual stack)
    uint32_t counter_id = 1; // IPv6 connect counter
    increment_counter(counter_id);

    // Copy the IPv6 address (could be IPv4-mapped for dual stack)
    __builtin_memcpy(entry.destination_ip.ipv6, ctx->user_ip6, sizeof(ctx->user_ip6));
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    // Find the entry in the policy map.
    destination_entry_value_t* policy = bpf_map_lookup_elem(&dual_stack_test_policy_map, &entry);
    if (policy != NULL) {
        bpf_printk("Dual stack test: IPv6 (possibly dual stack) redirect to proxy");
        
        if (bpf_sock_addr_set_redirect_context(ctx, redirect_context, sizeof(redirect_context)) < 0) {
            return verdict;
        }
        
        __builtin_memcpy(ctx->user_ip6, policy->destination_ip.ipv6, sizeof(ctx->user_ip6));
        ctx->user_port = policy->destination_port;

        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    return verdict;
}

SEC("cgroup/connect4")
int
dual_stack_connect_redirect4(bpf_sock_addr_t* ctx)
{
    return dual_stack_redirect_v4(ctx);
}

SEC("cgroup/connect6")
int
dual_stack_connect_redirect6(bpf_sock_addr_t* ctx)
{
    return dual_stack_redirect_v6(ctx);
}