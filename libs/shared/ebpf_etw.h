// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Declarations for eBPF ETW.

#pragma once

#ifndef _KERNEL_MODE
#define MCGEN_CONTROL_CALLBACK 1
#endif

#include <ebpf_etw_gen.h>

#ifndef _KERNEL_MODE
#undef EventRegisterEbpfForWindowsProvider
#define EventRegisterEbpfForWindowsProvider() STATUS_SUCCESS
#undef EventUnregisterEbpfForWindowsProvider
#define EventUnregisterEbpfForWindowsProvider()
#endif
