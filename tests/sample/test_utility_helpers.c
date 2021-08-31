// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// eBPF program for testing utility general helper functions.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"
#include "sample_test_common.h"

#define VALUE_SIZE 32

SEC("maps")
struct bpf_map utility_map = {
    .size = sizeof(struct bpf_map),
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(ebpf_utility_helpers_data_t),
    .max_entries = UTILITY_MAP_SIZE};

SEC("xdp")
int
test_program_entry(xdp_md_t* context)
{
    uint32_t keys[UTILITY_MAP_SIZE] = {0, 1};
    ebpf_utility_helpers_data_t test_data = {0};

    // get a random number.
    test_data.random = bpf_get_prandom_u32();

    // get current timestamp.
    test_data.timestamp = bpf_ktime_get_boot_ns();

    // get current cpu ID.
    test_data.cpu_id = bpf_get_smp_processor_id();

    // Write into test utility_map index 0.
    bpf_map_update_elem(&utility_map, &keys[0], &test_data, 0);

    // get another random number.
    test_data.random = bpf_get_prandom_u32();

    // get current timestamp.
    test_data.timestamp = bpf_ktime_get_boot_ns();

    // Write into test utility_map index 1.
    bpf_map_update_elem(&utility_map, &keys[1], &test_data, 0);

    return 0;
}
