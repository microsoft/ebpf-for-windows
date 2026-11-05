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

// Define a macro that defines a program which tail calls a function for the sample hook.
#define DEFINE_SAMPLE_TAIL_FUNC(x)                                          \
    SEC("sample_ext/" #x)                                                   \
    uint32_t sample_test_callee##x(sample_program_context_t* ctx)           \
    {                                                                       \
        int i = x + 1;                                                      \
        bpf_printk("Calling tail call index [x = %d], [x+1 = %d]\n", x, i); \
        if (bpf_tail_call(ctx, &sample_tail_call_map, i) < 0) {             \
            bpf_printk("Tail call failed at index %d\n", i);                \
        }                                                                   \
        return 2;                                                           \
    }

#define DECLARE_SAMPLE_TAIL_FUNC(x) uint32_t sample_test_callee##x(sample_program_context_t* ctx);

DECLARE_SAMPLE_TAIL_FUNC(0)
DECLARE_SAMPLE_TAIL_FUNC(1)
DECLARE_SAMPLE_TAIL_FUNC(2)
DECLARE_SAMPLE_TAIL_FUNC(3)
DECLARE_SAMPLE_TAIL_FUNC(4)
DECLARE_SAMPLE_TAIL_FUNC(5)
DECLARE_SAMPLE_TAIL_FUNC(6)
DECLARE_SAMPLE_TAIL_FUNC(7)
DECLARE_SAMPLE_TAIL_FUNC(8)
DECLARE_SAMPLE_TAIL_FUNC(9)
DECLARE_SAMPLE_TAIL_FUNC(10)
DECLARE_SAMPLE_TAIL_FUNC(11)
DECLARE_SAMPLE_TAIL_FUNC(12)
DECLARE_SAMPLE_TAIL_FUNC(13)
DECLARE_SAMPLE_TAIL_FUNC(14)
DECLARE_SAMPLE_TAIL_FUNC(15)
DECLARE_SAMPLE_TAIL_FUNC(16)
DECLARE_SAMPLE_TAIL_FUNC(17)
DECLARE_SAMPLE_TAIL_FUNC(18)
DECLARE_SAMPLE_TAIL_FUNC(19)
DECLARE_SAMPLE_TAIL_FUNC(20)
DECLARE_SAMPLE_TAIL_FUNC(21)
DECLARE_SAMPLE_TAIL_FUNC(22)
DECLARE_SAMPLE_TAIL_FUNC(23)
DECLARE_SAMPLE_TAIL_FUNC(24)
DECLARE_SAMPLE_TAIL_FUNC(25)
DECLARE_SAMPLE_TAIL_FUNC(26)
DECLARE_SAMPLE_TAIL_FUNC(27)
DECLARE_SAMPLE_TAIL_FUNC(28)
DECLARE_SAMPLE_TAIL_FUNC(29)
DECLARE_SAMPLE_TAIL_FUNC(30)
DECLARE_SAMPLE_TAIL_FUNC(31)
DECLARE_SAMPLE_TAIL_FUNC(32)
DECLARE_SAMPLE_TAIL_FUNC(33)
DECLARE_SAMPLE_TAIL_FUNC(34)

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, uint32_t);
    __uint(max_entries, MAX_TAIL_CALL_CNT + 2);
    __array(values, uint32_t(sample_program_context_t* ctx));
} sample_tail_call_map SEC(".maps") = {
    .values = {
        sample_test_callee0,  sample_test_callee1,  sample_test_callee2,  sample_test_callee3,  sample_test_callee4,
        sample_test_callee5,  sample_test_callee6,  sample_test_callee7,  sample_test_callee8,  sample_test_callee9,
        sample_test_callee10, sample_test_callee11, sample_test_callee12, sample_test_callee13, sample_test_callee14,
        sample_test_callee15, sample_test_callee16, sample_test_callee17, sample_test_callee18, sample_test_callee19,
        sample_test_callee20, sample_test_callee21, sample_test_callee22, sample_test_callee23, sample_test_callee24,
        sample_test_callee25, sample_test_callee26, sample_test_callee27, sample_test_callee28, sample_test_callee29,
        sample_test_callee30, sample_test_callee31, sample_test_callee32, sample_test_callee33, sample_test_callee34,
    }};

DEFINE_SAMPLE_TAIL_FUNC(0)
DEFINE_SAMPLE_TAIL_FUNC(1)
DEFINE_SAMPLE_TAIL_FUNC(2)
DEFINE_SAMPLE_TAIL_FUNC(3)
DEFINE_SAMPLE_TAIL_FUNC(4)
DEFINE_SAMPLE_TAIL_FUNC(5)
DEFINE_SAMPLE_TAIL_FUNC(6)
DEFINE_SAMPLE_TAIL_FUNC(7)
DEFINE_SAMPLE_TAIL_FUNC(8)
DEFINE_SAMPLE_TAIL_FUNC(9)
DEFINE_SAMPLE_TAIL_FUNC(10)
DEFINE_SAMPLE_TAIL_FUNC(11)
DEFINE_SAMPLE_TAIL_FUNC(12)
DEFINE_SAMPLE_TAIL_FUNC(13)
DEFINE_SAMPLE_TAIL_FUNC(14)
DEFINE_SAMPLE_TAIL_FUNC(15)
DEFINE_SAMPLE_TAIL_FUNC(16)
DEFINE_SAMPLE_TAIL_FUNC(17)
DEFINE_SAMPLE_TAIL_FUNC(18)
DEFINE_SAMPLE_TAIL_FUNC(19)
DEFINE_SAMPLE_TAIL_FUNC(20)
DEFINE_SAMPLE_TAIL_FUNC(21)
DEFINE_SAMPLE_TAIL_FUNC(22)
DEFINE_SAMPLE_TAIL_FUNC(23)
DEFINE_SAMPLE_TAIL_FUNC(24)
DEFINE_SAMPLE_TAIL_FUNC(25)
DEFINE_SAMPLE_TAIL_FUNC(26)
DEFINE_SAMPLE_TAIL_FUNC(27)
DEFINE_SAMPLE_TAIL_FUNC(28)
DEFINE_SAMPLE_TAIL_FUNC(29)
DEFINE_SAMPLE_TAIL_FUNC(30)
DEFINE_SAMPLE_TAIL_FUNC(31)
DEFINE_SAMPLE_TAIL_FUNC(32)
DEFINE_SAMPLE_TAIL_FUNC(33)

uint32_t sample_test_caller(sample_program_context_t* ctx);

SEC("sample_ext")
uint32_t
sample_test_caller(sample_program_context_t* ctx)
{
    bpf_printk("sample_test_caller: Start tail caller.\n");
    if (bpf_tail_call(ctx, &sample_tail_call_map, 0) < 0) {
        bpf_printk("Failed tail call index %d\n", 0);
    }

    return 2;
}

SEC("sample_ext/34")
uint32_t
sample_test_callee34(sample_program_context_t* ctx)
{
    bpf_printk("Last tail call index: sample_test_callee34\n");
    return 1;
}
