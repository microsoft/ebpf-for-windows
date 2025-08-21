// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_endian.h"
#include "bpf_helpers.h"

struct value
{
    uint32_t current_pid;
    uint64_t start_key;
} value;

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct value);
    __uint(max_entries, 1);
} process_start_key_map SEC(".maps");

SEC("sockops")
int
func(bpf_sock_ops_t* ctx)
{
    const uint16_t ebpf_test_port = 0x3bbf; // Host byte order.

    if (ctx->local_port == ebpf_test_port || ctx->remote_port == ebpf_test_port)
    {
        uint64_t start_key = bpf_get_current_process_start_key();
        uint64_t pid_tgid = bpf_get_current_pid_tgid();
        struct value value = {.current_pid = pid_tgid >> 32, .start_key = start_key};
        uint32_t key = 0;
        bpf_map_update_elem(&process_start_key_map, &key, &value, 0);
    }

    return 0;
}