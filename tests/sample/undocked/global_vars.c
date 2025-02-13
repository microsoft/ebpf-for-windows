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

// Note:
// .rodata section is read-only data section and has size of 4 bytes (int)
// .data section is data section and has size of 8 bytes (2 * int)
// .bss section is uninitialized data section and has size of 4 bytes (int)
static const volatile int global_var = 10; // This is inserted into the .rodata section
static volatile int global_var2 = 20;      // This is inserted into the .data section
static volatile int global_var3;           // This is inserted into the .bss section
static volatile int global_var4 = 40;      // This is also inserted into the .data section

SEC("sample_ext")
int
GlobalVariableTest(sample_program_context_t* ctx)
{
    global_var3 = global_var + global_var2;
    global_var3 += global_var4;
    return 0;
}
