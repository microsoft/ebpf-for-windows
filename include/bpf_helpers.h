// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

// On Linux, including the bpf_helpers.h in libbpf must be done after including
// a platform-specific include file such as vmlinux.h or linux/types.h which makes
// it not quite platform-agnostic today.  We hope this to change in the future
// once libbpf itself becomes cross-platform (issue #351).  In the meantime,
// this version of bpf_helpers.h is already cross-platform.

// Include platform-specific definitions.
#include "ebpf_structs.h"
#include "bpf_helpers_platform.h"

// If we're compiling an actual eBPF program, then include
// libbpf's bpf_helpers.h for the rest of the platform-agnostic
// defines.
#ifndef _MSC_VER
#include "../external/bpftool/libbpf/src/bpf_helpers.h"
#endif

#ifndef __doxygen
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

#include "bpf_helper_defs.h"

#define MAX_TAIL_CALL_CNT 32
