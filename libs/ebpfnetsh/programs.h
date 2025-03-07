// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include <windows.h>
#include <netsh.h>

#ifdef __cplusplus
extern "C"
{
#endif

    FN_HANDLE_CMD handle_ebpf_add_program;
    FN_HANDLE_CMD handle_ebpf_delete_program;
    FN_HANDLE_CMD handle_ebpf_pin_program;
    FN_HANDLE_CMD handle_ebpf_set_program;
    FN_HANDLE_CMD handle_ebpf_show_programs;
    FN_HANDLE_CMD handle_ebpf_unpin_program;

#ifdef __cplusplus
}
#endif
