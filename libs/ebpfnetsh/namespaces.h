// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include <windows.h>
#include <netsh.h>

#ifdef __cplusplus
extern "C"
{
#endif

    FN_HANDLE_CMD handle_ebpf_set_thread_namespace;
    FN_HANDLE_CMD handle_ebpf_show_namespace;

#ifdef __cplusplus
}

bool
ebpf_netsh_has_namespace_argument(LPWSTR* argv, DWORD current_index, DWORD argc) noexcept;

unsigned long
ebpf_netsh_namespace_command(
    FN_HANDLE_CMD* handler,
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD current_index,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done);

#define EBPF_NETSH_NAMESPACE_OVERRIDE(handler)                                                               \
    if (ebpf_netsh_has_namespace_argument(argv, current_index, argc)) {                                      \
        return ebpf_netsh_namespace_command(handler, machine, argv, current_index, argc, flags, data, done); \
    }

#endif
