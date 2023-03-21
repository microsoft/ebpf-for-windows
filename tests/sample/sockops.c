// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "net/ip.h"
#include "socket_tests_common.h"

SEC("maps")
struct bpf_map_def connection_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(connection_tuple_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1};

SEC("maps")
struct bpf_map_def audit_map = {.type = BPF_MAP_TYPE_RINGBUF, .max_entries = 256 * 1024};

inline int
handle_v4(bpf_sock_ops_t* ctx, bool outbound, bool connected)
{
    int result = 0;
    audit_entry_t audit_entry = {0};

    audit_entry.tuple.src_ip.ipv4 = (outbound) ? ctx->local_ip4 : ctx->remote_ip4;
    audit_entry.tuple.src_port = (outbound) ? ctx->local_port : ctx->remote_port;
    audit_entry.tuple.dst_ip.ipv4 = (outbound) ? ctx->remote_ip4 : ctx->local_ip4;
    audit_entry.tuple.dst_port = (outbound) ? ctx->remote_port : ctx->local_port;
    audit_entry.tuple.protocol = ctx->protocol;
    audit_entry.tuple.interface_luid = ctx->interface_luid;
    audit_entry.outbound = outbound;
    audit_entry.connected = connected;

    if (bpf_map_lookup_elem(&connection_map, &audit_entry.tuple) != NULL) {
        result = bpf_ringbuf_output(&audit_map, &audit_entry, sizeof(audit_entry), 0);
    }

    return result;
}

inline int
handle_v6(bpf_sock_ops_t* ctx, bool outbound, bool connected)
{
    int result = 0;
    audit_entry_t audit_entry = {0};
    void* ip6 = NULL;

    ip6 = (outbound) ? ctx->local_ip6 : ctx->remote_ip6;
    __builtin_memcpy(audit_entry.tuple.src_ip.ipv6, ip6, sizeof(uint32_t) * 4);
    audit_entry.tuple.src_port = (outbound) ? ctx->local_port : ctx->remote_port;
    ip6 = (outbound) ? ctx->remote_ip6 : ctx->local_ip6;
    __builtin_memcpy(audit_entry.tuple.dst_ip.ipv6, ip6, sizeof(uint32_t) * 4);
    audit_entry.tuple.dst_port = (outbound) ? ctx->remote_port : ctx->local_port;
    audit_entry.tuple.protocol = ctx->protocol;
    audit_entry.tuple.interface_luid = ctx->interface_luid;
    audit_entry.outbound = outbound;
    audit_entry.connected = connected;

    if (bpf_map_lookup_elem(&connection_map, &audit_entry.tuple) != NULL) {
        result = bpf_ringbuf_output(&audit_map, &audit_entry, sizeof(audit_entry), 0);
    }

    return result;
}

SEC("sockops")
int
connection_monitor(bpf_sock_ops_t* ctx)
{
    int result = 0;
    bool outbound;
    bool connected;
    switch (ctx->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        outbound = true;
        connected = true;
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        outbound = false;
        connected = true;
        break;
    case BPF_SOCK_OPS_CONNECTION_DELETED_CB:
        outbound = false;
        connected = false;
        break;
    default:
        result = -1;
    }
    if (result == 0) {
        result = (ctx->family == AF_INET) ? handle_v4(ctx, outbound, connected) : handle_v6(ctx, outbound, connected);
    }

    return result;
}
