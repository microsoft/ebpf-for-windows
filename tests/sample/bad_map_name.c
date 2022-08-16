// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

#include "bpf_helpers.h"

SEC("maps")
struct bpf_map_def this_map_has_a_name_that_is_longer_than_what_the_ebofcore_driver_can_support = {
    .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 1};

SEC("xdp_prog") int lookup(struct xdp_md* ctx)
{
    uint32_t key = 0;
    void* value =
        bpf_map_lookup_elem(&this_map_has_a_name_that_is_longer_than_what_the_ebofcore_driver_can_support, &key);
    return (value == NULL);
}
