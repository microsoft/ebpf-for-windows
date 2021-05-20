// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <guiddef.h>

// This file contains eBPF definitions needed by eBPF programs as well as
// the verifier and execution context.

typedef GUID ebpf_program_type_t;
typedef GUID ebpf_attach_type_t;

typedef enum _ebpf_helper_function
{
    EBPF_LOOKUP_ELEMENT = 1,
    EBPF_UPDATE_ELEMENT = 2,
    EBPF_DELETE_ELEMENT = 3,
} ebpf_helper_function_t;
