// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// This program conditionally selects between two array maps before calling
// bpf_map_lookup_elem. Since the verifier cannot determine which map is
// being accessed at the call site, bpf2c cannot inline the array lookup
// and must fall back to invoking the helper function.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} map_a SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} map_b SEC(".maps");

SEC("bind")
int
ambiguous_map_lookup(bind_md_t* ctx)
{
    uint32_t key = 0;

    // Pick which map to query based on context. The verifier tracks both
    // possibilities, so bpf2c sees an ambiguous map fd at the call site
    // and falls back to the generic helper call.
    void* map;
    if (ctx->process_id & 1) {
        map = &map_a;
    } else {
        map = &map_b;
    }

    uint64_t* value = bpf_map_lookup_elem(map, &key);
    if (value) {
        return (int)*value;
    }
    return 0;
}
