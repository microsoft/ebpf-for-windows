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

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} this_map_has_a_name_that_is_longer_than_what_the_ebpfcore_driver_can_support SEC(".maps");

SEC("sample_ext") int lookup(sample_program_context_t* ctx)
{
    uint32_t key = 0;
    void* value =
        bpf_map_lookup_elem(&this_map_has_a_name_that_is_longer_than_what_the_ebpfcore_driver_can_support, &key);
    return (value == NULL);
}
