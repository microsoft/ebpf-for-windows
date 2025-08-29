// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_endian.h"
#include "bpf_helpers.h"

struct val
{
    uint32_t current_tid;
    int64_t start_time;
} val;

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct val);
    __uint(max_entries, 1);
} thread_start_time_map SEC(".maps");

SEC("sockops")
int
func(bpf_sock_ops_t* ctx)
{
    struct val v = {.current_tid = 0, .start_time = 0};
    uint64_t pid_tgid = bpf_get_current_pid_tgid();

    v.start_time = bpf_get_thread_create_time();
    v.current_tid = pid_tgid & 0xFFFFFFFF;
    uint32_t key = 0;
    bpf_map_update_elem(&thread_start_time_map, &key, &v, 0);

    return 0;
}