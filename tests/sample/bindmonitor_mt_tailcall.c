// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c bindmonitor_mt_tailcall.c -o bindmonitor_mt_tailcall_jit.o
//
// For bpf code: clang -target bpf -O2 -Werror -c bindmonitor_tailcall.c -o bindmonitor_tailcall.o
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
struct bpf_map_def prog_array_map = {
    .type = BPF_MAP_TYPE_PROG_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 8};

SEC("maps")
// Dummy map. Should not be populated by UM.
struct bpf_map_def dummy_map = {
    .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 1000};

#define BIND_TAIL_FUNC(x)                                                    \
    SEC("bind/" #x)                                                          \
    bind_action_t BindMonitor_Callee##x(bind_md_t* ctx)                      \
    {                                                                        \
        uint32_t dummy_key = 0;                                              \
        uint32_t* dummy_value = bpf_map_lookup_elem(&dummy_map, &dummy_key); \
                                                                             \
        if (!dummy_value) {                                                  \
            int index = x;                                                   \
            bpf_tail_call(ctx, &prog_array_map, index);                      \
        }                                                                    \
                                                                             \
        return BIND_DENY;                                                    \
    }

BIND_TAIL_FUNC(0)
BIND_TAIL_FUNC(1)
BIND_TAIL_FUNC(2)
BIND_TAIL_FUNC(3)
BIND_TAIL_FUNC(4)
BIND_TAIL_FUNC(5)
BIND_TAIL_FUNC(6)
BIND_TAIL_FUNC(7)
BIND_TAIL_FUNC(8)
BIND_TAIL_FUNC(9)
BIND_TAIL_FUNC(10)
BIND_TAIL_FUNC(11)
BIND_TAIL_FUNC(12)
BIND_TAIL_FUNC(13)
BIND_TAIL_FUNC(14)
BIND_TAIL_FUNC(15)
BIND_TAIL_FUNC(16)
BIND_TAIL_FUNC(17)
BIND_TAIL_FUNC(18)
BIND_TAIL_FUNC(19)
BIND_TAIL_FUNC(20)
BIND_TAIL_FUNC(21)
BIND_TAIL_FUNC(22)
BIND_TAIL_FUNC(23)
BIND_TAIL_FUNC(24)
BIND_TAIL_FUNC(25)
BIND_TAIL_FUNC(26)
BIND_TAIL_FUNC(27)
BIND_TAIL_FUNC(28)
BIND_TAIL_FUNC(29)
BIND_TAIL_FUNC(30)

// The following line is optional, but is used to verify
// that the BindMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
bind_hook_t BindMonitor_Callee0;

SEC("bind/31")
bind_action_t
BindMonitor_Callee31(bind_md_t* ctx)
{
    return BIND_PERMIT;
}
