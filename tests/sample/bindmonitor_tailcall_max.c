// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c bindmonitor_mt_tailcall.c -o bindmonitor_mt_tailcall_jit.o
//
// For bpf code: clang -target bpf -O2 -Werror -c bindmonitor_mt_tailcall.c -o bindmonitor_mt_tailcall.o
// this passes the checker

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
    bind_action_t BindMonitor_Test_Callee##x(bind_md_t* ctx)                \
    {                                                                       \
        int i = x + 1;                                                      \
        bpf_printk("Calling Tail call index [x = %d], [x+1 = %d]\n", x, i); \
        if (bpf_tail_call(ctx, &bind_tail_call_map, i) < 0) {               \
            bpf_printk("Tail call failed at index %d\n", i);                \
        }                                                                   \
        return BIND_DENY;                                                   \
    }

#define DECLARE_BIND_TAIL_FUNC(x) bind_action_t BindMonitor_Test_Callee##x(bind_md_t* ctx);

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
    __uint(max_entries, MAX_TAIL_CALL_CNT + 3);
    __array(values, bind_action_t(bind_md_t* ctx));
} bind_tail_call_map SEC(".maps") = {
    .values = {
        BindMonitor_Test_Callee0,  BindMonitor_Test_Callee1,  BindMonitor_Test_Callee2,  BindMonitor_Test_Callee3,
        BindMonitor_Test_Callee4,  BindMonitor_Test_Callee5,  BindMonitor_Test_Callee6,  BindMonitor_Test_Callee7,
        BindMonitor_Test_Callee8,  BindMonitor_Test_Callee9,  BindMonitor_Test_Callee10, BindMonitor_Test_Callee11,
        BindMonitor_Test_Callee12, BindMonitor_Test_Callee13, BindMonitor_Test_Callee14, BindMonitor_Test_Callee15,
        BindMonitor_Test_Callee16, BindMonitor_Test_Callee17, BindMonitor_Test_Callee18, BindMonitor_Test_Callee19,
        BindMonitor_Test_Callee20, BindMonitor_Test_Callee21, BindMonitor_Test_Callee22, BindMonitor_Test_Callee23,
        BindMonitor_Test_Callee24, BindMonitor_Test_Callee25, BindMonitor_Test_Callee26, BindMonitor_Test_Callee27,
        BindMonitor_Test_Callee28, BindMonitor_Test_Callee29, BindMonitor_Test_Callee30, BindMonitor_Test_Callee31,
        BindMonitor_Test_Callee32, BindMonitor_Test_Callee33, BindMonitor_Test_Callee34,

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

// This line verifies that the BindMonitor_Caller prototype is correct by declaring a bind_hook_t
// variable with the same name as the first tail call function.
// This line is optional.
bind_hook_t BindMonitor_Test_Caller;

SEC("bind")
bind_action_t
BindMonitor_Test_Caller(bind_md_t* ctx)
{
    bpf_printk("Start Tail call index %d\n", 0);
    if (bpf_tail_call(ctx, &bind_tail_call_map, 0) < 0) {
        bpf_printk("Failed Tail call index %d\n", 0);
        return BIND_DENY;
    }

    return BIND_DENY;
}

SEC("bind/34")
bind_action_t
BindMonitor_Test_Callee34(bind_md_t* ctx)
{
    bpf_printk("Last Tail call index: BindMonitor_Test_Callee34\n");
    // This function is the last tail call function for the bind hook.
    // This function returns BIND_PERMIT to allow the bind request to proceed.
    return BIND_PERMIT;
}
