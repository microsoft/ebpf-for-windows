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

SEC("maps")
struct bpf_map map = {BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 33};

SEC("maps") struct bpf_map canary = {BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

// Define a program that calls the next program in the array.
// The first program in the array is at index 0.
// The last program in the array is at index 32.
// Each program increments the value in the canary map at index 0.
// If the canary value is not equal to the program index, the program returns 1
// which will cause the test to fail.
#define TAIL_CALL(X)                                           \
    SEC("xdp_prog" #X) int sequential##X(struct xdp_md* ctx)   \
    {                                                          \
        uint32_t key = 0;                                      \
        uint32_t* value;                                       \
        value = (uint32_t*)bpf_map_lookup_elem(&canary, &key); \
        if (!value) {                                          \
            return 1;                                          \
        }                                                      \
        bpf_printk("sequential" #X ": *value=%d\n", *value);   \
        if (*value != X) {                                     \
            return 1;                                          \
        }                                                      \
        (*value)++;                                            \
        return bpf_tail_call(ctx, &map, X + 1);                \
    }

TAIL_CALL(0)
TAIL_CALL(1)
TAIL_CALL(2)
TAIL_CALL(3)
TAIL_CALL(4)
TAIL_CALL(5)
TAIL_CALL(6)
TAIL_CALL(7)
TAIL_CALL(8)
TAIL_CALL(9)
TAIL_CALL(10)
TAIL_CALL(11)
TAIL_CALL(12)
TAIL_CALL(13)
TAIL_CALL(14)
TAIL_CALL(15)
TAIL_CALL(16)
TAIL_CALL(17)
TAIL_CALL(18)
TAIL_CALL(19)
TAIL_CALL(20)
TAIL_CALL(21)
TAIL_CALL(22)
TAIL_CALL(23)
TAIL_CALL(24)
TAIL_CALL(25)
TAIL_CALL(26)
TAIL_CALL(27)
TAIL_CALL(28)
TAIL_CALL(29)
TAIL_CALL(30)
TAIL_CALL(31)
TAIL_CALL(32)
