// Copyright (c) eBPF for Windows contributors
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

/**
 * @brief Sample program demonstrating bpf_sock_addr_get_network_context()
 * for CONNECT_AUTHORIZATION attach points. This program shows how to retrieve
 * network layer properties using the versioned struct-based helper.
 */

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/ip.h"

typedef unsigned int ULONG;
#include "ipifcons.h"

// Test port for socket connections.
#define SOCKET_TEST_PORT 8989

// Map to store network context results for verification.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, bpf_sock_addr_network_context_t);
    __uint(max_entries, 1000);
} network_context_map SEC(".maps");

// Map to store connection count for testing.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} connection_count_map SEC(".maps");

/**
 * @brief Test program for CONNECT_AUTHORIZATION IPv4 that demonstrates bpf_sock_addr_get_network_context.
 */
SEC("cgroup/connect_authorization4")
int
test_sock_addr_helpers_v4(bpf_sock_addr_t* ctx)
{
    int retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

    // Only process TCP connections for testing.
    if (ctx->protocol != IPPROTO_TCP) {
        goto exit;
    }

    // Generate a unique connection ID based on address and port.
    uint32_t connection_id = ctx->user_ip4 ^ (ctx->user_port << 16);

    // Retrieve network context using the struct-based helper.
    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        // Network context unavailable; fail closed.
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    // Store results for verification.
    bpf_map_update_elem(&network_context_map, &connection_id, &net_ctx, BPF_ANY);

    // Update connection counter.
    uint32_t counter_key = 1;
    uint64_t count = 1;
    uint64_t* existing_count = bpf_map_lookup_elem(&connection_count_map, &counter_key);
    if (existing_count) {
        count = *existing_count + 1;
    }
    bpf_map_update_elem(&connection_count_map, &counter_key, &count, BPF_ANY);

exit:
    return retval;
}

/**
 * @brief Test program for CONNECT_AUTHORIZATION IPv6 that demonstrates bpf_sock_addr_get_network_context.
 */
SEC("cgroup/connect_authorization6")
int
test_sock_addr_helpers_v6(bpf_sock_addr_t* ctx)
{
    int retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

    // Only process TCP connections for testing.
    if (ctx->protocol != IPPROTO_TCP) {
        goto exit;
    }

    // Generate a unique connection ID for IPv6 (simplified hash).
    uint32_t connection_id = (ctx->user_ip6[0] ^ ctx->user_ip6[3]) ^ (ctx->user_port << 16);

    // Retrieve network context using the struct-based helper.
    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    // Store results for verification.
    bpf_map_update_elem(&network_context_map, &connection_id, &net_ctx, BPF_ANY);

    // Update connection counter.
    uint32_t counter_key = 2; // Different key for IPv6.
    uint64_t count = 1;
    uint64_t* existing_count = bpf_map_lookup_elem(&connection_count_map, &counter_key);
    if (existing_count) {
        count = *existing_count + 1;
    }
    bpf_map_update_elem(&connection_count_map, &counter_key, &count, BPF_ANY);

exit:
    return retval;
}

/**
 * @brief Demonstration program showing conditional logic based on network context.
 */
SEC("cgroup/connect_authorization4")
int
conditional_authorization_v4(bpf_sock_addr_t* ctx)
{
    int retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

    if (ctx->protocol != IPPROTO_TCP) {
        goto exit;
    }

    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    // 1. Block connections through certain interface types.
    if (net_ctx.interface_type == IF_TYPE_PPP) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    // 2. Log connections through tunnels.
    if (net_ctx.tunnel_type != 0) {
        uint32_t tunnel_key = 100;
        uint64_t tunnel_count = 1;
        uint64_t* existing_tunnel_count = bpf_map_lookup_elem(&connection_count_map, &tunnel_key);
        if (existing_tunnel_count) {
            tunnel_count = *existing_tunnel_count + 1;
        }
        bpf_map_update_elem(&connection_count_map, &tunnel_key, &tunnel_count, BPF_ANY);
    }

exit:
    return retval;
}

/**
 * @brief Test program for RECV_ACCEPT IPv4 that demonstrates bpf_sock_addr_get_network_context
 * works at the recv_accept attach point (not just connect_authorization).
 */
SEC("cgroup/recv_accept4")
int
test_recv_accept_helpers_v4(bpf_sock_addr_t* ctx)
{
    int retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

    if (ctx->protocol != IPPROTO_TCP) {
        goto exit;
    }

    uint32_t connection_id = ctx->user_ip4 ^ (ctx->user_port << 16);

    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    bpf_map_update_elem(&network_context_map, &connection_id, &net_ctx, BPF_ANY);

    uint32_t counter_key = 3; // Different key for recv_accept.
    uint64_t count = 1;
    uint64_t* existing_count = bpf_map_lookup_elem(&connection_count_map, &counter_key);
    if (existing_count) {
        count = *existing_count + 1;
    }
    bpf_map_update_elem(&connection_count_map, &counter_key, &count, BPF_ANY);

exit:
    return retval;
}