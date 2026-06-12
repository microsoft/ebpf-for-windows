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

// Test eBPF program for EBPF_PROGRAM_TYPE_SAMPLE implemented in
// the Sample eBPF extension.

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"
#include "sample_common_routines.h"
#include "sample_ext_helpers.h"
#include "sample_test_common.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 64);
} redirect_map SEC(".maps");

SEC("sample_ext")
int
test_sample_redirect_map(sample_program_context_t* context)
{
    (void)context;

    // Call the bpf_redirect_map helper function. This should succeed because the
    // sample extension implements the global virtual bpf_redirect_map helper.
    intptr_t result = bpf_redirect_map(&redirect_map, 0, 0);

    bpf_printk("redirect_map result: %d\n", (int)result);

    return 0;
}
