// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test: noinline subprogram call inside a loop.
// Validates that the Prevail verifier handles noinline calls inside loops.

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} bpf2bpf_loop_map SEC(".maps");

// Noinline subprogram: increments the supplied value by 1 and returns it.
__attribute__((noinline)) uint32_t
increment(uint32_t value)
{
    return value + 1;
}

// Noinline call INSIDE a loop — 10 increments, writes 10 to map.
SEC("sample_ext")
uint32_t
caller_with_loop(sample_program_context_t* ctx)
{
    uint32_t key = 0;
    uint32_t counter = 0;

    for (volatile int i = 0; i < 10; i++) {
        counter = increment(counter);
    }

    bpf_map_update_elem(&bpf2bpf_loop_map, &key, &counter, 0);
    return counter;
}
