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
// Counter key scheme: 1=connect_v4, 2=connect_v6, 3=recv_accept_v4, 4=bind_v4, 5=bind_v6.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} connection_count_map SEC(".maps");

// Per-bind helper-return values captured by the bind test programs. Keyed by
// address family (4 for bind4, 6 for bind6). The test reads this back to verify
// that each supported helper is callable and returns a plausible value at the
// bind attach point.
typedef struct _bind_helper_results
{
    uint64_t pid_tgid; ///< bpf_get_current_pid_tgid (upper 32 bits = caller PID, lower 32 bits = caller TID).
    uint64_t logon_id; ///< bpf_get_current_logon_id.
    int32_t is_admin;  ///< bpf_is_current_admin (0, 1, or negative on error).
    int32_t set_redirect_context; ///< bpf_sock_addr_set_redirect_context return value (expected -1 at bind).
    int64_t socket_cookie;        ///< bpf_get_socket_cookie.
} bind_helper_results_t;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, bind_helper_results_t);
    __uint(max_entries, 4);
} bind_helper_results_map SEC(".maps");

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
    // XOR first and last dwords of IPv6 address for a simple connection ID hash.
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

/**
 * @brief Test program for BIND IPv4 that exercises bpf_sock_addr_get_network_context and
 * the additional helpers supported at the bind attach point
 * (bpf_get_current_pid_tgid, bpf_get_current_logon_id, bpf_is_current_admin,
 * bpf_get_socket_cookie, bpf_sock_addr_set_redirect_context).
 */
SEC("cgroup/bind4")
int
test_bind_helpers_v4(bpf_sock_addr_t* ctx)
{
    int retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

    // Generate a key from local bind address and port.
    uint32_t connection_id = ctx->user_ip4 ^ (ctx->user_port << 16);

    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    bpf_map_update_elem(&network_context_map, &connection_id, &net_ctx, BPF_ANY);

    // Capture results from each additional bind-supported helper. The user-mode
    // test reads back bind_helper_results_map[4] to validate each value.
    // bpf_sock_addr_set_redirect_context is documented as not supported at bind and
    // is expected to return -1; pass a small stack buffer so the helper has something
    // valid to point at.
    uint32_t redirect_data = 0;
    bind_helper_results_t results = {0};
    results.pid_tgid = bpf_get_current_pid_tgid();
    results.logon_id = bpf_get_current_logon_id(ctx);
    results.is_admin = bpf_is_current_admin(ctx);
    results.set_redirect_context = bpf_sock_addr_set_redirect_context(ctx, &redirect_data, sizeof(redirect_data));
    results.socket_cookie = bpf_get_socket_cookie(ctx);
    uint32_t results_key = 4;
    bpf_map_update_elem(&bind_helper_results_map, &results_key, &results, BPF_ANY);

    uint32_t counter_key = 4; // Different key for bind4.
    uint64_t count2 = 1;
    uint64_t* existing_count2 = bpf_map_lookup_elem(&connection_count_map, &counter_key);
    if (existing_count2) {
        count2 = *existing_count2 + 1;
    }
    bpf_map_update_elem(&connection_count_map, &counter_key, &count2, BPF_ANY);

exit:
    return retval;
}

/**
 * @brief Test program for LISTEN IPv4 that demonstrates bpf_sock_addr_get_network_context
 * works at the listen attach point.
 */
SEC("cgroup/listen4")
int
test_listen_helpers_v4(bpf_sock_addr_t* ctx)
{
    int retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

    // Generate a key from local listen address and port.
    uint32_t connection_id = ctx->user_ip4 ^ (ctx->user_port << 16);

    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    bpf_map_update_elem(&network_context_map, &connection_id, &net_ctx, BPF_ANY);

    uint32_t counter_key = 6; // Different key for listen4.
    uint64_t count2 = 1;
    uint64_t* existing_count2 = bpf_map_lookup_elem(&connection_count_map, &counter_key);
    if (existing_count2) {
        count2 = *existing_count2 + 1;
    }
    bpf_map_update_elem(&connection_count_map, &counter_key, &count2, BPF_ANY);

exit:
    return retval;
}

/**
 * @brief Test program for BIND IPv6 that exercises bpf_sock_addr_get_network_context and
 * the additional helpers supported at the bind attach point
 * (bpf_get_current_pid_tgid, bpf_get_current_logon_id, bpf_is_current_admin,
 * bpf_get_socket_cookie, bpf_sock_addr_set_redirect_context).
 */
SEC("cgroup/bind6")
int
test_bind_helpers_v6(bpf_sock_addr_t* ctx)
{
    int retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

    // XOR first and last dwords of IPv6 address for a simple connection ID hash.
    uint32_t connection_id = (ctx->user_ip6[0] ^ ctx->user_ip6[3]) ^ (ctx->user_port << 16);

    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    bpf_map_update_elem(&network_context_map, &connection_id, &net_ctx, BPF_ANY);

    // Capture results from each additional bind-supported helper. See bind4 program for details.
    uint32_t redirect_data = 0;
    bind_helper_results_t results = {0};
    results.pid_tgid = bpf_get_current_pid_tgid();
    results.logon_id = bpf_get_current_logon_id(ctx);
    results.is_admin = bpf_is_current_admin(ctx);
    results.set_redirect_context = bpf_sock_addr_set_redirect_context(ctx, &redirect_data, sizeof(redirect_data));
    results.socket_cookie = bpf_get_socket_cookie(ctx);
    uint32_t results_key = 6;
    bpf_map_update_elem(&bind_helper_results_map, &results_key, &results, BPF_ANY);

    uint32_t counter_key = 5; // Different key for bind6.
    uint64_t count3 = 1;
    uint64_t* existing_count3 = bpf_map_lookup_elem(&connection_count_map, &counter_key);
    if (existing_count3) {
        count3 = *existing_count3 + 1;
    }
    bpf_map_update_elem(&connection_count_map, &counter_key, &count3, BPF_ANY);

exit:
    return retval;
}

/**
 * @brief Test program for LISTEN IPv6 that demonstrates bpf_sock_addr_get_network_context
 * works at the listen attach point.
 */
SEC("cgroup/listen6")
int
test_listen_helpers_v6(bpf_sock_addr_t* ctx)
{
    int retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

    uint32_t connection_id = (ctx->user_ip6[0] ^ ctx->user_ip6[3]) ^ (ctx->user_port << 16);

    bpf_sock_addr_network_context_t net_ctx = {};
    if (bpf_sock_addr_get_network_context(ctx, &net_ctx, sizeof(net_ctx)) < 0) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    bpf_map_update_elem(&network_context_map, &connection_id, &net_ctx, BPF_ANY);

    uint32_t counter_key = 7; // Different key for listen6.
    uint64_t count3 = 1;
    uint64_t* existing_count3 = bpf_map_lookup_elem(&connection_count_map, &counter_key);
    if (existing_count3) {
        count3 = *existing_count3 + 1;
    }
    bpf_map_update_elem(&connection_count_map, &counter_key, &count3, BPF_ANY);

exit:
    return retval;
}