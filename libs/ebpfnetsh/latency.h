// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include <windows.h>
#include <netsh.h>

#ifdef __cplusplus
extern "C"
{
#endif

    FN_HANDLE_CMD handle_ebpf_set_latency;
    FN_HANDLE_CMD handle_ebpf_show_latency;
    FN_HANDLE_CMD handle_ebpf_start_latencytrace;
    FN_HANDLE_CMD handle_ebpf_stop_latencytrace;
    FN_HANDLE_CMD handle_ebpf_show_latencytrace;

#ifdef __cplusplus
}
#endif
