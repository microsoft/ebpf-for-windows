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

// The following line is optional, but is used to verify
// that the BindMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
bind_hook_t UtilityTest;

SEC("bind")
bind_action_t
UtilityTest(bind_md_t* ctx)
{
    char test1[] = "test";
    char test2[] = "test";
    char test3[] = "1234567890";

    // Verify that the memcmp function returns 0 when the strings are equal.
    if (memcmp(test1, test2, 4) != 0) {
        return 1;
    }

    test1[0] = 'T';
    // Verify that the memcmp function returns < 0 when the first string is less than the second.
    if (memcmp(test1, test2, 4) >= 0) {
        return 2;
    }

    // Verify that bpf_memcmp_s handles the case where the first string is shorter than the second.
    // The overlapping portion of the strings is equal, but the first string is shorter, so it should return < 0.
    if (bpf_memcmp_s(test1, 3, test2, 4) >= 0) {
        return 3;
    }

    // Alter the first string so that it is no longer equal to the second.
    test1[0] = 'T';
    test1[1] = 'E';
    test1[2] = 'S';
    test1[3] = 'T';

    // Use memcpy to overwrite the first string with the second.
    if (memcpy(test1, test2, 4) < 0) {
        return 4;
    }

    // Verify that the first string is now equal to the second.
    if (test1[0] != 't' || test1[1] != 'e' || test1[2] != 's' || test1[3] != 't') {
        return 5;
    }

    // Verify that memset overwrites the first string with 0.
    if (memset(test1, 0, 4) == 0) {
        return 6;
    }

    // Verify that all characters in the first string are now 0.
    if (test1[0] != 0 || test1[1] != 0 || test1[2] != 0 || test1[3] != 0) {
        return 7;
    }

    // Verify that memmove can move the second string to the first string when the strings overlap.
    if (memmove(test3 + 2, test3, 4) < 0) {
        return 8;
    }

    // Verify that the contents of the second string are now in the first string.
    if (test3[2] != '1' || test3[3] != '2' || test3[4] != '3' || test3[5] != '4') {
        return 9;
    }

    return 0;
}
