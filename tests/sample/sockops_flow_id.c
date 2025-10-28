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

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"
#include "net/ip.h"
#include "socket_tests_common.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, connection_tuple_t);
    __type(value, uint64_t);
    __uint(max_entries, 10);
} flow_id_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} flow_id_audit_map SEC(".maps");

typedef struct _flow_id_audit_entry
{
    connection_tuple_t tuple;
    uint64_t flow_id;
    uint64_t process_id;
    uint32_t operation;
    bool outbound;
    bool connected;
} flow_id_audit_entry_t;

inline int
update_flow_id_audit_map(flow_id_audit_entry_t* audit_entry)
{
    return bpf_ringbuf_output(&flow_id_audit_map, audit_entry, sizeof(*audit_entry), 0);
}

inline int
handle_v4_flow_id(bpf_sock_ops_t* ctx, bool outbound, bool connected)
{
    int result = 0;
    flow_id_audit_entry_t audit_entry = {0};

    // Get the WFP flow ID using the new helper function.
    uint64_t flow_id = bpf_sock_ops_get_flow_id(ctx);

    audit_entry.tuple.local_ip.ipv4 = ctx->local_ip4;
    audit_entry.tuple.local_port = ctx->local_port;
    audit_entry.tuple.remote_ip.ipv4 = ctx->remote_ip4;
    audit_entry.tuple.remote_port = ctx->remote_port;
    audit_entry.tuple.protocol = ctx->protocol;
    audit_entry.tuple.interface_luid = ctx->interface_luid;
    audit_entry.process_id = bpf_get_current_pid_tgid();
    // Ignore the thread Id.
    audit_entry.process_id >>= 32;
    audit_entry.outbound = outbound;
    audit_entry.connected = connected;
    audit_entry.operation = ctx->op;
    audit_entry.flow_id = flow_id;

    // Store the flow ID in our map for later verification.
    bpf_map_update_elem(&flow_id_map, &audit_entry.tuple, &flow_id, BPF_ANY);

    return update_flow_id_audit_map(&audit_entry);
}

inline int
handle_v6_flow_id(bpf_sock_ops_t* ctx, bool outbound, bool connected)
{
    int result = 0;
    flow_id_audit_entry_t audit_entry = {0};

    // Get the WFP flow ID using the new helper function.
    uint64_t flow_id = bpf_sock_ops_get_flow_id(ctx);

    // Copy IPv6 addresses.
    __builtin_memcpy(&audit_entry.tuple.local_ip.ipv6, &ctx->local_ip6, sizeof(audit_entry.tuple.local_ip.ipv6));
    __builtin_memcpy(&audit_entry.tuple.remote_ip.ipv6, &ctx->remote_ip6, sizeof(audit_entry.tuple.remote_ip.ipv6));

    audit_entry.tuple.local_port = ctx->local_port;
    audit_entry.tuple.remote_port = ctx->remote_port;
    audit_entry.tuple.protocol = ctx->protocol;
    audit_entry.tuple.interface_luid = ctx->interface_luid;
    audit_entry.process_id = bpf_get_current_pid_tgid();
    // Ignore the thread Id.
    audit_entry.process_id >>= 32;
    audit_entry.outbound = outbound;
    audit_entry.connected = connected;
    audit_entry.operation = ctx->op;
    audit_entry.flow_id = flow_id;

    // Store the flow ID in our map for later verification
    bpf_map_update_elem(&flow_id_map, &audit_entry.tuple, &flow_id, BPF_ANY);

    return update_flow_id_audit_map(&audit_entry);
}

SEC("sockops")
int
flow_id_monitor(bpf_sock_ops_t* ctx)
{
    switch (ctx->op) {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        if (ctx->family == AF_INET) {
            return handle_v4_flow_id(ctx, false, true);
        } else if (ctx->family == AF_INET6) {
            return handle_v6_flow_id(ctx, false, true);
        }
        break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        if (ctx->family == AF_INET) {
            return handle_v4_flow_id(ctx, true, true);
        } else if (ctx->family == AF_INET6) {
            return handle_v6_flow_id(ctx, true, true);
        }
        break;
    case BPF_SOCK_OPS_CONNECTION_DELETED_CB:
        if (ctx->family == AF_INET) {
            return handle_v4_flow_id(ctx, false, false);
        } else if (ctx->family == AF_INET6) {
            return handle_v6_flow_id(ctx, false, false);
        }
        break;
    }

    return 0;
}

char _license[] SEC("license") = "MIT";