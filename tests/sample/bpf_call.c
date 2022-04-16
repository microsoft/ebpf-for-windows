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

SEC("maps") struct bpf_map map = {BPF_MAP_TYPE_ARRAY, 2, 4, 512};

SEC("xdp_prog") int func(struct xdp_md* ctx)
{
    uint32_t key = 0;
    uint32_t value = 42;
    int result = bpf_map_update_elem(&map, &key, &value, 0);
    return result;
}
