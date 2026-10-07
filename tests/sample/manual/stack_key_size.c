// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} array_map SEC(".maps");

typedef struct _stack_key
{
    volatile uint8_t padding[510];
    uint16_t key;
} stack_key_t;

SEC("bind/1")
int
prog1(bind_md_t* ctx)
{
    stack_key_t stack_key;

    stack_key.padding[0] = 0;
    stack_key.padding[sizeof(stack_key.padding) - 1] = 0;
    stack_key.key = (uint16_t)ctx->process_id;

    return bpf_map_lookup_elem(&array_map, &stack_key.key) != NULL;
}

SEC("bind/2")
int
prog2(bind_md_t* ctx)
{
    uint16_t key = (uint16_t)ctx->process_id;
    return bpf_map_lookup_elem(&array_map, &key) != NULL;
}
