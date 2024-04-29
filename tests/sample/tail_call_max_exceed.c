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

// Define a macro that defines a program which tail calls a function for the bind hook.
#define DEFINE_BIND_TAIL_FUNC(x)                                            \
    SEC("bind/" #x)                                                         \
    bind_action_t bind_test_callee##x(bind_md_t* ctx)                       \
    {                                                                       \
        int i = x + 1;                                                      \
        bpf_printk("Calling tail call index [x = %d], [x+1 = %d]\n", x, i); \
        if (bpf_tail_call(ctx, &bind_tail_call_map, i) < 0) {               \
            bpf_printk("Tail call failed at index %d\n", i);                \
        }                                                                   \
        return BIND_DENY;                                                   \
    }

#define DECLARE_BIND_TAIL_FUNC(x) bind_action_t bind_test_callee##x(bind_md_t* ctx);

DECLARE_BIND_TAIL_FUNC(0)
DECLARE_BIND_TAIL_FUNC(1)
DECLARE_BIND_TAIL_FUNC(2)
DECLARE_BIND_TAIL_FUNC(3)
DECLARE_BIND_TAIL_FUNC(4)
DECLARE_BIND_TAIL_FUNC(5)
DECLARE_BIND_TAIL_FUNC(6)
DECLARE_BIND_TAIL_FUNC(7)
DECLARE_BIND_TAIL_FUNC(8)
DECLARE_BIND_TAIL_FUNC(9)
DECLARE_BIND_TAIL_FUNC(10)
DECLARE_BIND_TAIL_FUNC(11)
DECLARE_BIND_TAIL_FUNC(12)
DECLARE_BIND_TAIL_FUNC(13)
DECLARE_BIND_TAIL_FUNC(14)
DECLARE_BIND_TAIL_FUNC(15)
DECLARE_BIND_TAIL_FUNC(16)
DECLARE_BIND_TAIL_FUNC(17)
DECLARE_BIND_TAIL_FUNC(18)
DECLARE_BIND_TAIL_FUNC(19)
DECLARE_BIND_TAIL_FUNC(20)
DECLARE_BIND_TAIL_FUNC(21)
DECLARE_BIND_TAIL_FUNC(22)
DECLARE_BIND_TAIL_FUNC(23)
DECLARE_BIND_TAIL_FUNC(24)
DECLARE_BIND_TAIL_FUNC(25)
DECLARE_BIND_TAIL_FUNC(26)
DECLARE_BIND_TAIL_FUNC(27)
DECLARE_BIND_TAIL_FUNC(28)
DECLARE_BIND_TAIL_FUNC(29)
DECLARE_BIND_TAIL_FUNC(30)
DECLARE_BIND_TAIL_FUNC(31)
DECLARE_BIND_TAIL_FUNC(32)
DECLARE_BIND_TAIL_FUNC(33)
DECLARE_BIND_TAIL_FUNC(34)

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, uint32_t);
    __uint(max_entries, MAX_TAIL_CALL_CNT + 2);
    __array(values, bind_action_t(bind_md_t* ctx));
} bind_tail_call_map SEC(".maps") = {
    .values = {
        bind_test_callee0,  bind_test_callee1,  bind_test_callee2,  bind_test_callee3,  bind_test_callee4,
        bind_test_callee5,  bind_test_callee6,  bind_test_callee7,  bind_test_callee8,  bind_test_callee9,
        bind_test_callee10, bind_test_callee11, bind_test_callee12, bind_test_callee13, bind_test_callee14,
        bind_test_callee15, bind_test_callee16, bind_test_callee17, bind_test_callee18, bind_test_callee19,
        bind_test_callee20, bind_test_callee21, bind_test_callee22, bind_test_callee23, bind_test_callee24,
        bind_test_callee25, bind_test_callee26, bind_test_callee27, bind_test_callee28, bind_test_callee29,
        bind_test_callee30, bind_test_callee31, bind_test_callee32, bind_test_callee33, bind_test_callee34,
    }};

DEFINE_BIND_TAIL_FUNC(0)
DEFINE_BIND_TAIL_FUNC(1)
DEFINE_BIND_TAIL_FUNC(2)
DEFINE_BIND_TAIL_FUNC(3)
DEFINE_BIND_TAIL_FUNC(4)
DEFINE_BIND_TAIL_FUNC(5)
DEFINE_BIND_TAIL_FUNC(6)
DEFINE_BIND_TAIL_FUNC(7)
DEFINE_BIND_TAIL_FUNC(8)
DEFINE_BIND_TAIL_FUNC(9)
DEFINE_BIND_TAIL_FUNC(10)
DEFINE_BIND_TAIL_FUNC(11)
DEFINE_BIND_TAIL_FUNC(12)
DEFINE_BIND_TAIL_FUNC(13)
DEFINE_BIND_TAIL_FUNC(14)
DEFINE_BIND_TAIL_FUNC(15)
DEFINE_BIND_TAIL_FUNC(16)
DEFINE_BIND_TAIL_FUNC(17)
DEFINE_BIND_TAIL_FUNC(18)
DEFINE_BIND_TAIL_FUNC(19)
DEFINE_BIND_TAIL_FUNC(20)
DEFINE_BIND_TAIL_FUNC(21)
DEFINE_BIND_TAIL_FUNC(22)
DEFINE_BIND_TAIL_FUNC(23)
DEFINE_BIND_TAIL_FUNC(24)
DEFINE_BIND_TAIL_FUNC(25)
DEFINE_BIND_TAIL_FUNC(26)
DEFINE_BIND_TAIL_FUNC(27)
DEFINE_BIND_TAIL_FUNC(28)
DEFINE_BIND_TAIL_FUNC(29)
DEFINE_BIND_TAIL_FUNC(30)
DEFINE_BIND_TAIL_FUNC(31)
DEFINE_BIND_TAIL_FUNC(32)
DEFINE_BIND_TAIL_FUNC(33)

bind_hook_t bind_test_caller;

SEC("bind")
bind_action_t
bind_test_caller(bind_md_t* ctx)
{
    bpf_printk("bind_test_caller: Start tail caller.\n");
    if (bpf_tail_call(ctx, &bind_tail_call_map, 0) < 0) {
        bpf_printk("Failed tail call index %d\n", 0);
    }

    return BIND_DENY;
}

SEC("bind/34")
bind_action_t
bind_test_callee34(bind_md_t* ctx)
{
    bpf_printk("Last tail call index: bind_test_callee34\n");
    // This function is the last tail call function for the bind hook.
    // This function returns BIND_PERMIT to allow the bind request to proceed.
    return BIND_PERMIT;
}
