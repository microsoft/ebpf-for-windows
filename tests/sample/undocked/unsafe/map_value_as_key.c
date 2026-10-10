// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} array_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint16_t);
    __uint(max_entries, 1);
} hashmap1 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} hashmap2 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} hashmap3 SEC(".maps");

SEC("sample_ext/1")
int
prog1(sample_program_context_t* ctx)
{
    uint32_t key = ctx->uint32_data;
    uint16_t* value = bpf_map_lookup_elem(&hashmap1, &key);
    return value != NULL && bpf_map_lookup_elem(&array_map, value) != NULL;
}

SEC("sample_ext/2")
int
prog2(sample_program_context_t* ctx)
{
    uint32_t key = ctx->uint32_data;
    uint32_t* value = bpf_map_lookup_elem(&hashmap2, &key);
    return value != NULL && bpf_map_lookup_elem(&array_map, value) != NULL;
}

SEC("sample_ext/3")
int
prog3(sample_program_context_t* ctx)
{
    uint32_t key = ctx->uint32_data;
    uint64_t* value = bpf_map_lookup_elem(&hashmap3, &key);
    return value != NULL && bpf_map_lookup_elem(&array_map, value) != NULL;
}
