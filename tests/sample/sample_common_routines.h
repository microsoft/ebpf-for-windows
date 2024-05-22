// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Common routines that eBPF sample programs can invoke.

#include "bpf_helpers.h"
#include "sample_test_common.h"

inline int
test_utility_helper_functions(void* utility_map)
{
    uint32_t keys[UTILITY_MAP_SIZE] = {0, 1};
    ebpf_utility_helpers_data_t test_data = {0};

    // Get a random number.
    test_data.random = bpf_get_prandom_u32();

    // Test assumes time stamps are ordered as follows:
    // test_data[0].boot_timestamp
    // test_data[0].timestamp
    // test_data[1].timestamp
    // test_data[1].boot_timestamp
    // Get current timestamp.
    test_data.boot_timestamp = bpf_ktime_get_boot_ns();

    // Get current timestamp.
    test_data.timestamp = bpf_ktime_get_ns();

    // Get current cpu ID.
    test_data.cpu_id = bpf_get_smp_processor_id();

    // Get the process / thread ID.
    test_data.pid_tgid = bpf_get_current_pid_tgid();

    // Write into test utility_map index 0.
    bpf_map_update_elem(utility_map, &keys[0], &test_data, 0);

    // Get another random number.
    test_data.random = bpf_get_prandom_u32();

    // Get current timestamp.
    test_data.timestamp = bpf_ktime_get_ns();

    // Get current timestamp.
    test_data.boot_timestamp = bpf_ktime_get_boot_ns();

    // Get the process / thread ID.
    test_data.pid_tgid = bpf_get_current_pid_tgid();

    // Write into test utility_map index 1.
    bpf_map_update_elem(utility_map, &keys[1], &test_data, 0);

    return 0;
}
