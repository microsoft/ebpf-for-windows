// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Declarations for eBPF ETW.

#pragma once

//
// The ebpf_tracelog.h header fails to work properly when ETW headers are
// already included, so include tracelog first, even though ETW has no
// dependency on it.
//
#include <ebpf_tracelog.h>

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
