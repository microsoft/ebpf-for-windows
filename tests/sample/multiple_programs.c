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

SEC("sample_ext/2")
int
program3(sample_program_context_t* ctx)
{
    return 3;
}

SEC("sample_ext/4")
int
program1(sample_program_context_t* ctx)
{
    return 1;
}

SEC("sample_ext/3")
int
program2(sample_program_context_t* ctx)
{
    return 2;
}

SEC("sample_ext/1")
int
program4(sample_program_context_t* ctx)
{
    return 4;
}