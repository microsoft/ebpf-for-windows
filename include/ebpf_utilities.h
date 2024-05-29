// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_result.h"

#include <stdint.h>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

// This should be consistent with _ebpf_result_mapping[]
// in ebpf_error.c
_When_(error != ERROR_SUCCESS, _Ret_range_(1, 65535)) __forceinline ebpf_result_t
    win32_error_code_to_ebpf_result(uint32_t error)
{
    ebpf_result_t result;

    switch (error) {
    case ERROR_SUCCESS:
        result = EBPF_SUCCESS;
        break;

    case ERROR_OUTOFMEMORY:
    case ERROR_NOT_ENOUGH_MEMORY:
        result = EBPF_NO_MEMORY;
        break;

    case ERROR_PATH_NOT_FOUND:
        result = EBPF_OBJECT_NOT_FOUND;
        break;

    case ERROR_NOT_FOUND:
        result = EBPF_KEY_NOT_FOUND;
        break;

    case ERROR_INVALID_PARAMETER:
        result = EBPF_INVALID_ARGUMENT;
        break;

    case ERROR_NO_MORE_ITEMS:
    case ERROR_NO_MORE_MATCHES:
        result = EBPF_NO_MORE_KEYS;
        break;

    case ERROR_INVALID_HANDLE:
        result = EBPF_INVALID_FD;
        break;

    case ERROR_NOT_SUPPORTED:
        result = EBPF_OPERATION_NOT_SUPPORTED;
        break;

    case ERROR_MORE_DATA:
        result = EBPF_INSUFFICIENT_BUFFER;
        break;

    case ERROR_FILE_NOT_FOUND:
        result = EBPF_FILE_NOT_FOUND;
        break;

    case ERROR_ALREADY_INITIALIZED:
        result = EBPF_ALREADY_INITIALIZED;
        break;

    case ERROR_OBJECT_ALREADY_EXISTS:
        result = EBPF_OBJECT_ALREADY_EXISTS;
        break;

    case ERROR_IO_PENDING:
        result = EBPF_PENDING;
        break;

    case ERROR_VERIFIER_STOP:
        result = EBPF_VERIFICATION_FAILED;
        break;

    case ERROR_NONE_MAPPED:
        result = EBPF_JIT_COMPILATION_FAILED;
        break;

    case ERROR_BAD_DRIVER:
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        break;

    case ERROR_INVALID_FUNCTION:
        result = EBPF_INVALID_OBJECT;
        break;

    case ERROR_OBJECT_NAME_EXISTS:
        result = EBPF_ALREADY_PINNED;
        break;

    case ERROR_TOO_MANY_CMDS:
        result = EBPF_PROGRAM_TOO_LARGE;
        break;

    case RPC_S_CALL_FAILED:
        result = EBPF_RPC_EXCEPTION;
        break;

    case ERROR_BAD_EXE_FORMAT:
        result = EBPF_ELF_PARSING_FAILED;
        break;

    case ERROR_ACCESS_DENIED:
        result = EBPF_ACCESS_DENIED;
        break;

    case ERROR_NOT_OWNER:
        result = EBPF_NOT_PINNED;
        break;

    case ERROR_CONTENT_BLOCKED:
        result = EBPF_BLOCKED_BY_POLICY;
        break;

    case ERROR_ARITHMETIC_OVERFLOW:
        result = EBPF_ARITHMETIC_OVERFLOW;
        break;

    case ERROR_GENERIC_COMMAND_FAILED:
        result = EBPF_PROGRAM_LOAD_FAILED;
        break;

    case ERROR_ALREADY_REGISTERED:
        // Currently STATUS_ALREADY_REGISTERED is mapped to
        // ERROR_INTERNAL_ERROR instead of ERROR_ALREADY_REGISTERED.
    case ERROR_INTERNAL_ERROR:
        result = EBPF_KEY_ALREADY_EXISTS;
        break;

    case ERROR_TOO_MANY_NAMES:
        result = EBPF_NO_MORE_TAIL_CALLS;
        break;

    case ERROR_NO_SYSTEM_RESOURCES:
        result = EBPF_OUT_OF_SPACE;
        break;

    case ERROR_OPERATION_ABORTED:
        result = EBPF_CANCELED;
        break;

    case ERROR_NOACCESS:
        result = EBPF_INVALID_POINTER;
        break;

    case ERROR_TIMEOUT:
        result = EBPF_TIMEOUT;
        break;

    case ERROR_BAD_COMMAND:
        result = EBPF_STALE_ID;
        break;

    case ERROR_INVALID_STATE:
        result = EBPF_INVALID_STATE;
        break;

    case ERROR_RETRY:
        result = EBPF_TRY_AGAIN;
        break;

    default:
        result = EBPF_FAILED;
        break;
    }

    return result;
}
