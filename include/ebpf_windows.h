// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "framework.h"

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

typedef enum _ebpf_error_code
{
    EBPF_ERROR_SUCCESS,
    EBPF_ERROR_OUT_OF_RESOURCES,
    EBPF_ERROR_NOT_FOUND,
    EBPF_ERROR_INVALID_PARAMETER,
    EBPF_ERROR_BLOCKED_BY_POLICY,
    EBPF_ERROR_NO_MORE_KEYS,
    EBPF_ERROR_INVALID_HANDLE,
    EBPF_ERROR_NOT_SUPPORTED,
    EBPF_ERROR_DUPLICATE_NAME,
    EBPF_ERROR_ARITHMETIC_OVERFLOW,
    EBPF_ERROR_EXTENSION_FAILED_TO_LOAD,
    EBPF_ERROR_INSUFFICIENT_BUFFER,
} ebpf_error_code_t;
