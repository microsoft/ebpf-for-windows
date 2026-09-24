// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "sample_test_common.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} pidtgid_map SEC(".maps");

static __inline void
record_pid_tgid()
{
    uint32_t key = 0;
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pidtgid_map, &key, &pid_tgid, BPF_ANY);
}

SEC("cgroup/bind4")
int
sock_addr_program(bpf_sock_addr_t* context)
{
    if (context->user_port == bpf_htons(SOCKET_TEST_PORT)) {
        record_pid_tgid();
    }
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

SEC("sockops")
int
sock_ops_program(bpf_sock_ops_t* context)
{
    uint16_t test_port = bpf_htons(SOCKET_TEST_PORT);
    if (context->local_port == test_port || context->remote_port == test_port) {
        record_pid_tgid();
    }
    return 0;
}
