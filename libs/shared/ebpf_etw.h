// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Declarations for eBPF ETW.

#pragma once

#ifndef _KERNEL_MODE
#define EVENT_CONTROL_CODE_DISABLE_PROVIDER 0
#define EVENT_CONTROL_CODE_ENABLE_PROVIDER 1
#define EVENT_CONTROL_CODE_CAPTURE_STATE 2
#endif

#include <ebpf_etw_gen.h>

// #ifndef _KERNEL_MODE
// #undef EventRegisterEbpfForWindowsProvider
// #define EventRegisterEbpfForWindowsProvider() STATUS_SUCCESS
// #undef EventUnregisterEbpfForWindowsProvider
// #define EventUnregisterEbpfForWindowsProvider()
// #undef MCGEN_CONTROL_CALLBACK
// #endif
