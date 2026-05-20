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

SEC("sample_ext")
int
test_sample_invalid_redirect_map(sample_program_context_t* context)
{
    // Try to call the bpf_redirect_map helper function.
    // This should fail because the sample extension does not implement bpf_redirect_map.
    intptr_t result = bpf_redirect_map(context, 0, 0);

    bpf_printk("redirect_map result: %d\n", (int)result);

    return 0;
}
