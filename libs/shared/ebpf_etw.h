// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Declarations for eBPF ETW.

#pragma once

#ifndef _KERNEL_MODE
// The usersim configuration fails to load these constants from evntrace.h, so
// redefine them here.
#include <evntrace.h>
#ifndef EVENT_CONTROL_CODE_DISABLE_PROVIDER
#define EVENT_CONTROL_CODE_DISABLE_PROVIDER 0
#endif
#ifndef EVENT_CONTROL_CODE_ENABLE_PROVIDER
#define EVENT_CONTROL_CODE_ENABLE_PROVIDER 1
#endif
#ifndef EVENT_CONTROL_CODE_CAPTURE_STATE
#define EVENT_CONTROL_CODE_CAPTURE_STATE 2
#endif
#endif // _KERNEL_MODE

#include <ebpf_etw_gen.h>
