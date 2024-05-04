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

int
sequential0(sample_program_context_t* ctx);
int
sequential1(sample_program_context_t* ctx);
int
sequential2(sample_program_context_t* ctx);
int
sequential3(sample_program_context_t* ctx);
int
sequential4(sample_program_context_t* ctx);
int
sequential5(sample_program_context_t* ctx);
int
sequential6(sample_program_context_t* ctx);
int
sequential7(sample_program_context_t* ctx);
int
sequential8(sample_program_context_t* ctx);
int
sequential9(sample_program_context_t* ctx);
int
sequential10(sample_program_context_t* ctx);
int
sequential11(sample_program_context_t* ctx);
int
sequential12(sample_program_context_t* ctx);
int
sequential13(sample_program_context_t* ctx);
int
sequential14(sample_program_context_t* ctx);
int
sequential15(sample_program_context_t* ctx);
int
sequential16(sample_program_context_t* ctx);
int
sequential17(sample_program_context_t* ctx);
int
sequential18(sample_program_context_t* ctx);
int
sequential19(sample_program_context_t* ctx);
int
sequential20(sample_program_context_t* ctx);
int
sequential21(sample_program_context_t* ctx);
int
sequential22(sample_program_context_t* ctx);
int
sequential23(sample_program_context_t* ctx);
int
sequential24(sample_program_context_t* ctx);
int
sequential25(sample_program_context_t* ctx);
int
sequential26(sample_program_context_t* ctx);
int
sequential27(sample_program_context_t* ctx);
int
sequential28(sample_program_context_t* ctx);
int
sequential29(sample_program_context_t* ctx);
int
sequential30(sample_program_context_t* ctx);
int
sequential31(sample_program_context_t* ctx);
int
sequential32(sample_program_context_t* ctx);
int
sequential33(sample_program_context_t* ctx);
int
sequential34(sample_program_context_t* ctx);

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 35);
    __uint(key_size, sizeof(uint32_t));
    __array(values, int(sample_program_context_t* ctx));
} map SEC(".maps") = {
    .values = {sequential0,  sequential1,  sequential2,  sequential3,  sequential4,  sequential5,  sequential6,
               sequential7,  sequential8,  sequential9,  sequential10, sequential11, sequential12, sequential13,
               sequential14, sequential15, sequential16, sequential17, sequential18, sequential19, sequential20,
               sequential21, sequential22, sequential23, sequential24, sequential25, sequential26, sequential27,
               sequential28, sequential29, sequential30, sequential31, sequential32, sequential33, sequential34},
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
} canary SEC(".maps");

// Define a program that calls the next program in the array.
// There are 33 tail calls in the array, starting from index 1 to 33.
// The last program in the array is at index 33, to test MAX_TAIL_CALL_COUNT.
// Each program increments the value in the canary map at index 0.
// If the canary value is not equal to the program index, the program returns 1
// which will cause the test to fail.
#define TAIL_CALL(X)                                                      \
    SEC("sample_ext" #X) int sequential##X(sample_program_context_t* ctx) \
    {                                                                     \
        uint32_t key = 0;                                                 \
        uint32_t* value;                                                  \
        value = (uint32_t*)bpf_map_lookup_elem(&canary, &key);            \
        if (!value) {                                                     \
            return 1;                                                     \
        }                                                                 \
        bpf_printk("sequential" #X ": *value=%d\n", *value);              \
        if (*value != X) {                                                \
            return 1;                                                     \
        }                                                                 \
        (*value)++;                                                       \
        return bpf_tail_call(ctx, &map, X + 1);                           \
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
TAIL_CALL(33)
TAIL_CALL(34)
