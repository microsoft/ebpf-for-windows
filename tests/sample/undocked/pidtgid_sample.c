// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} pidtgid_map SEC(".maps");

SEC("sample_ext")
int
sample_program(sample_program_context_t* context)
{
    (void)context;
    uint32_t key = 0;
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pidtgid_map, &key, &pid_tgid, BPF_ANY);
    return 0;
}
