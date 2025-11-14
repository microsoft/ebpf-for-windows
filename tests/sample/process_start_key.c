// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_endian.h"
#include "bpf_helpers.h"

typedef struct _value
{
    uint32_t current_pid;
    uint64_t start_key;
} value_t;

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, value_t);
    __uint(max_entries, 1);
} process_start_key_map SEC(".maps");

int
get_start_key(bpf_sock_addr_t* ctx)
{
    value_t v = {.current_pid = 0, .start_key = 0};

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    v.start_key = bpf_get_current_process_start_key();
    v.current_pid = pid_tgid >> 32;
    uint32_t key = 0;
    bpf_map_update_elem(&process_start_key_map, &key, &v, 0);

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

SEC("cgroup/connect4")
int
function_v4(bpf_sock_addr_t* ctx)
{
    return get_start_key(ctx);
}

SEC("cgroup/connect6")
int
function_v6(bpf_sock_addr_t* ctx)
{
    return get_start_key(ctx);
}
