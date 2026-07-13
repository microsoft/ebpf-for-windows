// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_endian.h"
#include "bpf_helpers.h"

// Destination port used by the api_test send_traffic() helper. Keep in sync with
// SOCKET_TEST_PORT in tests/api_test/api_test.cpp.
#define SOCKET_TEST_PORT 0x3bbf

typedef struct _value
{
    uint32_t current_tid;
    int64_t start_time;
} value_t;

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, value_t);
    __uint(max_entries, 1);
} thread_start_time_map SEC(".maps");

int
get_thread_create_time(bpf_sock_addr_t* ctx)
{
    // sock_addr programs run for every connection on the system. Only capture this test's
    // own traffic (loopback:SOCKET_TEST_PORT) so an unrelated connection cannot overwrite the
    // result before the test reads it. user_port is in network byte order.
    if (ctx->user_port != bpf_htons(SOCKET_TEST_PORT)) {
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    value_t v = {.current_tid = 0, .start_time = 0};
    uint64_t pid_tgid = bpf_get_current_pid_tgid();

    v.start_time = bpf_get_current_thread_create_time();
    v.current_tid = pid_tgid & 0xFFFFFFFF;
    uint32_t key = 0;
    bpf_map_update_elem(&thread_start_time_map, &key, &v, 0);

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

SEC("cgroup/connect4")
int
function_v4(bpf_sock_addr_t* ctx)
{
    return get_thread_create_time(ctx);
}

SEC("cgroup/connect6")
int
function_v6(bpf_sock_addr_t* ctx)
{
    return get_thread_create_time(ctx);
}
