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
#include "ebpf_nethooks.h"

SEC("bind_2")
int
program3(bind_md_t* ctx)
{
    return 3;
}

SEC("bind_4")
int
program1(bind_md_t* ctx)
{
    return 1;
}

SEC("bind_3")
int
program2(bind_md_t* ctx)
{
    return 2;
}

SEC("bind_1")
int
program4(bind_md_t* ctx)
{
    return 4;
}