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
 * @brief Sample program demonstrating the new socket address helper functions
 * for CONNECT_AUTHORIZATION attach points. This program shows how to use the helper
 * functions to retrieve additional network layer properties.
 */

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/ip.h"

typedef unsigned int ULONG;
#include "ipifcons.h"

// Test port for socket connections.
#define SOCKET_TEST_PORT 8989

// Map to store interface type information.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 100);
} interface_type_map SEC(".maps");

// Map to store tunnel type information.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 100);
} tunnel_type_map SEC(".maps");

// Map to store next-hop interface LUID.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 100);
} next_hop_interface_map SEC(".maps");

// Map to store sub-interface index.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 100);
} sub_interface_map SEC(".maps");

// Map to store connection count for testing.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} connection_count_map SEC(".maps");

// Structure to store all helper function results for verification.
typedef struct _helper_results
{
    uint32_t interface_type;
    uint32_t tunnel_type;
    uint64_t next_hop_interface_luid;
    uint32_t sub_interface_index;
    uint32_t connection_id;
} helper_results_t;

// Map to store comprehensive test results.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, helper_results_t);
    __uint(max_entries, 1000);
} test_results_map SEC(".maps");

/**
 * @brief Test program for CONNECT_AUTHORIZATION IPv4 that demonstrates all new helper functions.
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

    // Test all new helper functions.
    uint32_t interface_type = bpf_sock_addr_get_interface_type(ctx);
    uint32_t tunnel_type = bpf_sock_addr_get_tunnel_type(ctx);
    uint64_t next_hop_interface_luid = bpf_sock_addr_get_next_hop_interface_luid(ctx);
    uint32_t sub_interface_index = bpf_sock_addr_get_sub_interface_index(ctx);

    // Store individual results in separate maps for easy verification.
    bpf_map_update_elem(&interface_type_map, &connection_id, &interface_type, BPF_ANY);
    bpf_map_update_elem(&tunnel_type_map, &connection_id, &tunnel_type, BPF_ANY);
    bpf_map_update_elem(&next_hop_interface_map, &connection_id, &next_hop_interface_luid, BPF_ANY);
    bpf_map_update_elem(&sub_interface_map, &connection_id, &sub_interface_index, BPF_ANY);

    // Store comprehensive results for detailed verification.
    helper_results_t results = {
        .interface_type = interface_type,
        .tunnel_type = tunnel_type,
        .next_hop_interface_luid = next_hop_interface_luid,
        .sub_interface_index = sub_interface_index,
        .connection_id = connection_id};
    bpf_map_update_elem(&test_results_map, &connection_id, &results, BPF_ANY);

    // Update connection counter.
    uint32_t counter_key = 1;
    uint64_t count = 1;
    uint64_t* existing_count = bpf_map_lookup_elem(&connection_count_map, &counter_key);
    if (existing_count) {
        count = *existing_count + 1;
    }
    bpf_map_update_elem(&connection_count_map, &counter_key, &count, BPF_ANY);

    // Example policy: Allow all connections but log the network properties.
    // In a real scenario, you could make authorization decisions based on
    // interface type, tunnel type, etc.

exit:
    return retval;
}

/**
 * @brief Test program for CONNECT_AUTHORIZATION IPv6 that demonstrates all new helper functions.
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

    // Test all new helper functions (same functions work for both IPv4 and IPv6).
    uint32_t interface_type = bpf_sock_addr_get_interface_type(ctx);
    uint32_t tunnel_type = bpf_sock_addr_get_tunnel_type(ctx);
    uint64_t next_hop_interface_luid = bpf_sock_addr_get_next_hop_interface_luid(ctx);
    uint32_t sub_interface_index = bpf_sock_addr_get_sub_interface_index(ctx);

    // Store individual results in separate maps for easy verification.
    bpf_map_update_elem(&interface_type_map, &connection_id, &interface_type, BPF_ANY);
    bpf_map_update_elem(&tunnel_type_map, &connection_id, &tunnel_type, BPF_ANY);
    bpf_map_update_elem(&next_hop_interface_map, &connection_id, &next_hop_interface_luid, BPF_ANY);
    bpf_map_update_elem(&sub_interface_map, &connection_id, &sub_interface_index, BPF_ANY);

    // Store comprehensive results for detailed verification.
    helper_results_t results = {
        .interface_type = interface_type,
        .tunnel_type = tunnel_type,
        .next_hop_interface_luid = next_hop_interface_luid,
        .sub_interface_index = sub_interface_index,
        .connection_id = connection_id};
    bpf_map_update_elem(&test_results_map, &connection_id, &results, BPF_ANY);

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
 * @brief Demonstration program showing conditional logic based on helper function results.
 */
SEC("cgroup/connect_authorization4")
int
conditional_auth_v4(bpf_sock_addr_t* ctx)
{
    int retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

    if (ctx->protocol != IPPROTO_TCP) {
        goto exit;
    }

    // Get network interface properties.
    uint32_t interface_type = bpf_sock_addr_get_interface_type(ctx);
    uint32_t tunnel_type = bpf_sock_addr_get_tunnel_type(ctx);

    // Example policy decisions based on network properties:

    // 1. Block connections through certain interface types.
    // (This is just an example - actual values would depend on your environment).
    if (interface_type == IF_TYPE_PPP) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
        goto exit;
    }

    // 2. Allow connections through tunnels with additional logging.
    if (tunnel_type != 0) { // Any tunnel type.
        // In a real scenario, you might log this to a separate map
        // or send information to userspace.
        uint32_t tunnel_key = 100; // Special key for tunnel connections.
        uint64_t tunnel_count = 1;
        uint64_t* existing_tunnel_count = bpf_map_lookup_elem(&connection_count_map, &tunnel_key);
        if (existing_tunnel_count) {
            tunnel_count = *existing_tunnel_count + 1;
        }
        bpf_map_update_elem(&connection_count_map, &tunnel_key, &tunnel_count, BPF_ANY);
    }

    // 3. Get next-hop interface for routing decisions.
    uint64_t next_hop_luid = bpf_sock_addr_get_next_hop_interface_luid(ctx);
    if (next_hop_luid != 0) {
        // Could make decisions based on which interface the traffic will route through.
        // For example, allow only certain outbound interfaces.
    }

    // 4. Sub-interface index for VLAN or similar scenarios.
    uint32_t sub_interface = bpf_sock_addr_get_sub_interface_index(ctx);
    if (sub_interface != 0) {
        // Could implement VLAN-based policies.
    }

exit:
    return retval;
}