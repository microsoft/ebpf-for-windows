// Copyright (c) eBPF for Windows contributors
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

SEC("maps")
struct bpf_map_def bind_tail_call_map = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_TAIL_CALL_CNT};

SEC("bind")
bind_action_t
BindMonitor_Caller(bind_md_t* ctx)
{
    bpf_printk("BindMonitor_Caller: Tail call index %d\n", 0);
    bpf_tail_call(ctx, &bind_tail_call_map, 0);

    return BIND_DENY;
}

// Define a macro that defines a program which tail calls a function for the bind hook.
#define DEFINE_BIND_TAIL_FUNC(x)                              \
    SEC("bind/" #x)                                           \
    bind_action_t BindMonitor_Callee##x(bind_md_t* ctx)       \
    {                                                         \
        int i = x + 1;                                        \
        bpf_printk("Tail call index %d\n", i);                \
        if (bpf_tail_call(ctx, &bind_tail_call_map, i) < 0) { \
            bpf_printk("Tail call failed at index %d\n", i);  \
        }                                                     \
                                                              \
        return BIND_DENY;                                     \
    }

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

// This line verifies that the BindMonitor_Caller prototype is correct by declaring a bind_hook_t
// variable with the same name as the first tail call function.
// This line is optional.
bind_hook_t BindMonitor_Caller;

SEC("bind/32")
bind_action_t
BindMonitor_Callee32(bind_md_t* ctx)
{
    // This function is the last tail call function for the bind hook.
    // This function returns BIND_PERMIT to allow the bind request to proceed.
    return BIND_PERMIT;
}
