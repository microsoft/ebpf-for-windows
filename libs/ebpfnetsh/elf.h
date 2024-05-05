// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include <windows.h>
#include <netsh.h>

#ifdef __cplusplus
extern "C"
{
#endif

    FN_HANDLE_CMD handle_ebpf_show_disassembly;
    FN_HANDLE_CMD handle_ebpf_show_sections;
    FN_HANDLE_CMD handle_ebpf_show_verification;

#ifdef __cplusplus
}
#endif
