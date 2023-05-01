// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netsh.h>

#ifdef __cplusplus
extern "C"
{
#endif

    FN_HANDLE_CMD handle_ebpf_show_processes;

#ifdef __cplusplus
}
#endif
