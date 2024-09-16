// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Declarations for eBPF ETW.

#pragma once

#ifndef _KERNEL_MODE
#define MCGEN_CONTROL_CALLBACK 1
#define McGenControlCallbackV2 NULL /* TODO define a dummy fn */
#endif

#include <ebpf_etw_gen.h>
