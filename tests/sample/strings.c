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

SEC("sample_ext")
int
StringOpsTest(sample_program_context_t* ctx)
{
    char buffer[20] = {};
    char test_str_1[6] = "alpha";
    char test_str_2[5] = "alfa";
    char test_buffer[] = {'a', 'l', 'p', 'h', 'a', 0, 'b', 'r', 'a', 'v', 'o', 0};
    char null_str = 0;

    if (bpf_strnlen_s(&null_str, 0) != 0) {
        return 1;
    }

    if (bpf_strnlen_s(buffer, 20) != 0) {
        return 2;
    }

    if (bpf_strnlen_s(test_str_1, 6) != 5) {
        return 3;
    }

    if (bpf_strnlen_s(test_buffer, sizeof(test_buffer)) != 5) {
        return 4;
    }

    if (bpf_strncpy_s(buffer, 20, test_str_1, 6) != 0) {
        return 5;
    }

    // Test that the first 6 bytes of buffer match the whole 6 bytes of test_str_1, including the
    // null terminators.
    if (bpf_memcmp_s(buffer, 6, test_str_1, 6) != 0) {
        return 6;
    }

    if (bpf_strncat_s(buffer, 20, test_str_2, 5) != 0) {
        return 7;
    }

    // length: 10
    char concat_buffer_state[] = "alphaalfa";

    // Test that the first 10 bytes of buffer match the expected state of concatenating those two
    // strings, including a null terminator in position 10.
    if (bpf_memcmp_s(buffer, 10, concat_buffer_state, 10) != 0) {
        return 8;
    }

    return 0;
}
