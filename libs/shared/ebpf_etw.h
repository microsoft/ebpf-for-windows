// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Declarations for eBPF ETW.

#pragma once

#ifdef _KERNEL_MODE
#include <ebpf_etw_gen.h>
//
// This is a workaround for MSVC compiler which does not allow straightforward
// passing of __VA_ARGS__ into another macro.
//
#ifndef __NESTED__
#define __NESTED__(x) x
#endif
#define ebpf_event_write(event, ...) __NESTED__({ event_write_##event(##__VA_ARGS__); })
#else
#define EventRegisterEbpfForWindowsProvider() STATUS_SUCCESS
#define EventUnregisterEbpfForWindowsProvider()
#define ebpf_event_write(...)
#endif
