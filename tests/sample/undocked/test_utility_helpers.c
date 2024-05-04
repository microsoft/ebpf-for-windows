// Copyright (c) eBPF for Windows contributors
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

// eBPF program for testing utility general helper functions.

#include "bpf_helpers.h"
#include "sample_common_routines.h"
#include "sample_ext_helpers.h"
#include "sample_test_common.h"

#define VALUE_SIZE 32

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, ebpf_utility_helpers_data_t);
    __uint(max_entries, UTILITY_MAP_SIZE);
} utility_map SEC(".maps");

SEC("sample_ext")
int
test_utility_helpers(sample_program_context_t* context)
{
    return test_utility_helper_functions(&utility_map);
}
