// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include <windows.h>
#include <netsh.h>

#ifdef __cplusplus
extern "C"
{
#endif

    FN_HANDLE_CMD handle_ebpf_pin_map;
    FN_HANDLE_CMD handle_ebpf_show_maps;
    FN_HANDLE_CMD handle_ebpf_unpin_map;

#ifdef __cplusplus
}
#endif
