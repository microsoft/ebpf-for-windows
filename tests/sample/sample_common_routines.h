// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Common routines that eBPF sample programs can invoke.

#include "ebpf_helpers.h"
#include "sample_test_common.h"

int
test_utility_helper_functions(struct bpf_map* utility_map)
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
    bpf_map_update_elem(utility_map, &keys[0], &test_data, 0);

    // get another random number.
    test_data.random = bpf_get_prandom_u32();

    // get current timestamp.
    test_data.timestamp = bpf_ktime_get_boot_ns();

    // Write into test utility_map index 1.
    bpf_map_update_elem(utility_map, &keys[1], &test_data, 0);

    return 0;
}
