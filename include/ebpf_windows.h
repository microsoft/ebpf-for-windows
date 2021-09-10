// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#ifdef _MSC_VER
#include <guiddef.h>
#else
typedef uint8_t GUID[16];
#endif

// This file contains eBPF definitions needed by eBPF programs as well as
// the verifier and execution context.

typedef GUID ebpf_program_type_t;
typedef GUID ebpf_attach_type_t;

typedef enum _ebpf_helper_function
{
    EBPF_LOOKUP_ELEMENT = 1, ///< Look up a map element.
    EBPF_UPDATE_ELEMENT = 2, ///< Update map element.
    EBPF_DELETE_ELEMENT = 3, ///< Delete a map element.
} ebpf_helper_function_t;
