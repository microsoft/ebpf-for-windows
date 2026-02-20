// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/ip.h"
#include "socket_tests_common.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint16_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} connect_authorization6_count_map SEC(".maps");

static const uint16_t remote_port = SOCKET_TEST_PORT;

SEC("cgroup/connect_authorization6")
int
count_tcp_connect_authorization6(bpf_sock_addr_t* ctx)
{
    int retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

    if (ctx->protocol != IPPROTO_TCP) {
        // Allow non-TCP connections.
        retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
        goto exit;
    }

    // IP address, port #s in the context are in network byte order.
    if (ctx->user_port != ntohs(remote_port)) {
        // Allow connections to other ports.
        retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
        goto exit;
    }

    // Get the current counter value (create new entry if not present).
    uint16_t key = remote_port;
    uint64_t value = 0;
    uint64_t* count = bpf_map_lookup_elem(&connect_authorization6_count_map, &key);
    if (!count) {
        value = 1;
        bpf_map_update_elem(&connect_authorization6_count_map, &key, &value, BPF_ANY);
    } else {
        value = *count + 1;
        bpf_map_update_elem(&connect_authorization6_count_map, &key, &value, BPF_EXIST);
    }

    // Example authorization logic: block every 3rd connection.
    if (value % 3 == 0) {
        retval = BPF_SOCK_ADDR_VERDICT_REJECT;
    } else {
        retval = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

exit:
    return retval;
}