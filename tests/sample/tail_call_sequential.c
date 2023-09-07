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

int
sequential0(struct xdp_md* ctx);
int
sequential1(struct xdp_md* ctx);
int
sequential2(struct xdp_md* ctx);
int
sequential3(struct xdp_md* ctx);
int
sequential4(struct xdp_md* ctx);
int
sequential5(struct xdp_md* ctx);
int
sequential6(struct xdp_md* ctx);
int
sequential7(struct xdp_md* ctx);
int
sequential8(struct xdp_md* ctx);
int
sequential9(struct xdp_md* ctx);
int
sequential10(struct xdp_md* ctx);
int
sequential11(struct xdp_md* ctx);
int
sequential12(struct xdp_md* ctx);
int
sequential13(struct xdp_md* ctx);
int
sequential14(struct xdp_md* ctx);
int
sequential15(struct xdp_md* ctx);
int
sequential16(struct xdp_md* ctx);
int
sequential17(struct xdp_md* ctx);
int
sequential18(struct xdp_md* ctx);
int
sequential19(struct xdp_md* ctx);
int
sequential20(struct xdp_md* ctx);
int
sequential21(struct xdp_md* ctx);
int
sequential22(struct xdp_md* ctx);
int
sequential23(struct xdp_md* ctx);
int
sequential24(struct xdp_md* ctx);
int
sequential25(struct xdp_md* ctx);
int
sequential26(struct xdp_md* ctx);
int
sequential27(struct xdp_md* ctx);
int
sequential28(struct xdp_md* ctx);
int
sequential29(struct xdp_md* ctx);
int
sequential30(struct xdp_md* ctx);
int
sequential31(struct xdp_md* ctx);
int
sequential32(struct xdp_md* ctx);

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 35);
    __uint(key_size, sizeof(uint32_t));
    __array(values, int(struct xdp_md* ctx));
} map SEC(".maps") = {
    .values =
        {
            sequential0,  sequential1,  sequential2,  sequential3,  sequential4,  sequential5,  sequential6,
            sequential7,  sequential8,  sequential9,  sequential10, sequential11, sequential12, sequential13,
            sequential14, sequential15, sequential16, sequential17, sequential18, sequential19, sequential20,
            sequential21, sequential22, sequential23, sequential24, sequential25, sequential26, sequential27,
            sequential28, sequential29, sequential30, sequential31, sequential32
        },
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
} canary SEC(".maps");

// The first top-level program.
SEC("xdp_prog") int sequential(struct xdp_md* ctx)
{
    return bpf_tail_call(ctx, &map, 0);
}

// Define a program that calls the next program in the array.
// There are 33 tail calls in the array, starting from index 0 to 32.
// The last program in the array is at index 33, to test MAX_TAIL_CALL_COUNT.
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
TAIL_CALL(33)
