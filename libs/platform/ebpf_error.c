// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#if !defined(_AMD64_)
#define _AMD64_
#endif
#include <ntdef.h>
#include <ntstatus.h>
#include <ebpf_result.h>

// This may need to be updated as part of issue:
// https://github.com/microsoft/ebpf-for-windows/issues/595
// This should be consistent with windows_error_to_ebpf_result()
// in api_common.hpp
NTSTATUS
ebpf_result_to_ntstatus(ebpf_result_t result)
{
    NTSTATUS status;
    switch (result) {
    case EBPF_SUCCESS: {
        status = STATUS_SUCCESS;
        break;
    }
    case EBPF_NO_MEMORY: {
        status = STATUS_INSUFFICIENT_RESOURCES;
        break;
    }
    case EBPF_KEY_NOT_FOUND: {
        status = STATUS_NOT_FOUND;
        break;
    }
    case EBPF_INVALID_ARGUMENT:
    case EBPF_INVALID_OBJECT: {
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    case EBPF_BLOCKED_BY_POLICY: {
        status = STATUS_CONTENT_BLOCKED;
        break;
    }
    case EBPF_NO_MORE_KEYS: {
        status = STATUS_NO_MORE_MATCHES;
        break;
    }
    case EBPF_INVALID_FD: {
        status = STATUS_INVALID_HANDLE;
        break;
    }
    case EBPF_OPERATION_NOT_SUPPORTED: {
        status = STATUS_NOT_SUPPORTED;
        break;
    }
    case EBPF_INSUFFICIENT_BUFFER: {
        status = STATUS_BUFFER_OVERFLOW;
        break;
    }
    case EBPF_OBJECT_ALREADY_EXISTS: {
        status = STATUS_OBJECT_NAME_EXISTS;
        break;
    }
    case EBPF_OBJECT_NOT_FOUND: {
        status = STATUS_OBJECT_PATH_NOT_FOUND;
        break;
    }
    case EBPF_EXTENSION_FAILED_TO_LOAD: {
        status = STATUS_UNSUCCESSFUL;
        break;
    }
    case EBPF_PENDING: {
        status = STATUS_PENDING;
        break;
    }
    default:
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}
