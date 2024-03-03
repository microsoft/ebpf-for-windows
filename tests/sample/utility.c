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
#include "ebpf_nethooks.h"

// The following line is optional, but is used to verify
// that the BindMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
bind_hook_t UtilityTest;

SEC("bind")
bind_action_t
UtilityTest(bind_md_t* ctx)
{
    // Memcmp test
    char test1[] = "test";
    char test2[] = "test";
    char test3[] = "1234567890";

    // Test equal
    if (memcmp(test1, test2, 4) != 0) {
        return 1;
    }

    test1[0] = 'T';
    // Test less than
    if (memcmp(test1, test2, 4) >= 0) {
        return 2;
    }

    // Test bpf_memcmp with different lengths.
    // This should return > 0 because the first 3 characters are the same and the second string is longer.
    if (bpf_memcmp(test1, 3, test2, 4) >= 0) {
        return 3;
    }

    test1[0] = 'T';
    test1[1] = 'E';
    test1[2] = 'S';
    test1[3] = 'T';

    // Test bpf_memcpy
    if (memcpy(test1, test2, 4) < 0) {
        return 4;
    }

    // Check if the copy worked
    if (test1[0] != 't' || test1[1] != 'e' || test1[2] != 's' || test1[3] != 't') {
        return 5;
    }

    // Test bpf_memset
    if (memset(test1, 4, 0) == 0) {
        return 6;
    }

    // Check if the memset worked
    if (test1[0] != 0 || test1[1] != 0 || test1[2] != 0 || test1[3] != 0) {
        return 7;
    }

    // Test bpf_memmove
    if (memmove(test3 + 2, test3, 4) < 0) {
        return 8;
    }

    // Check if the move worked
    if (test3[2] != '1' || test3[3] != '2' || test3[4] != '3' || test3[5] != '4') {
        return 9;
    }

    return 0;
}
