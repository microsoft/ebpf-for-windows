// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

// This program demonstrates how user mode can use the new ebpf_program_synchronize API to synchronize the state of two
// maps. The value in map_1 is used as a key in map_2, creating a dependency between the two maps.
// The problem is how to handle deleting entries from map_2 without causing inconsistencies with the value in
// map_1. If user mode first updates the value in map_1 and then deletes the entry in map_2, there may be
// programs that are still using the old value in map_1 as a key to map_2, which would lead to a lookup failure.
// To solve this, the user mode application must ensure that the key in map_2 can not be deleted until all programs that
// have used the old value in map_1 have been synchronized. This is done by using the ebpf_program_synchronize API to
// wait for all programs that may have seen the old value in map_1 to complete before allowing the deletion in map_2.

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} map_1 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} map_2 SEC(".maps");

// Stats map to track failures when the inner map lookup fails.
// Inner map lookup failures indicate a bug in the synchronization logic.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} failure_stats SEC(".maps");

SEC("sample_ext") int lookup(sample_program_context_t* ctx)
{
    uint32_t zero_key = 0;
    uint32_t* value_1;
    uint32_t* value_2;

    // Lookup in the first map.
    value_1 = bpf_map_lookup_elem(&map_1, &zero_key);
    if (!value_1) {
        // Increment failure stats if the lookup fails.
        uint32_t failure_key = 0;
        uint32_t* failure_count = bpf_map_lookup_elem(&failure_stats, &failure_key);
        if (failure_count) {
            __sync_fetch_and_add(failure_count, 1);
        }
        return 1; // Exit if the first lookup fails.
    }

    // Use the value from the first map as a key for the second map.
    value_2 = bpf_map_lookup_elem(&map_2, value_1);
    if (!value_2) {
        // Increment failure stats if the second lookup fails.
        uint32_t failure_key = 0;
        uint32_t* failure_count = bpf_map_lookup_elem(&failure_stats, &failure_key);
        if (failure_count) {
            __sync_fetch_and_add(failure_count, 1);
        }
        return 1; // Exit if the second lookup fails.
    }

    return 0;
}
