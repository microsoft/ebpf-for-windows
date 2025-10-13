// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_result.h"

#include <ntdef.h>
#include <ntstatus.h>

NTSTATUS
ebpf_result_to_ntstatus(ebpf_result_t result);