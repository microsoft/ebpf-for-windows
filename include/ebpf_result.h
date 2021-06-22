/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include <sal.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma warning(disable : 26812) // Prefer enum class
    typedef _Return_type_success_(return == EBPF_SUCCESS) enum ebpf_result {
        // The operation was successful.
        EBPF_SUCCESS,

        // Program verification failed.
        EBPF_VERIFICATION_FAILED,

        // JIT compilation failed.
        EBPF_JIT_COMPILATION_FAILED,

        // Program load failed.
        EBPF_PROGRAM_LOAD_FAILED,

        // Invalid FD provided.
        EBPF_INVALID_FD,

        // Invalid object provided (ebpf_object, ebpf_map, ebpf_program).
        EBPF_INVALID_OBJECT,

        // An invalid argument was supplied.
        EBPF_INVALID_ARGUMENT,

        // No pinned map or program exists for the path provided.
        EBPF_OBJECT_NOT_FOUND,

        // A program or map is already pinned with the same path.
        EBPF_OBJECT_ALREADY_EXISTS,

        // Invalid ELF file path.
        EBPF_FILE_NOT_FOUND,

        // The program or map already pinned to a different path.
        EBPF_ALREADY_PINNED,

        // The program or map is not pinned.
        EBPF_NOT_PINNED,

        // Low memory.
        EBPF_NO_MEMORY,

        // The program is too large.
        EBPF_PROGRAM_TOO_LARGE,

        // An RPC exception occurred.
        EBPF_RPC_EXCEPTION,

        // The handle was already initialized.
        EBPF_ALREADY_INITIALIZED,

        // A failure occurred in parsing the ELF file.
        EBPF_ELF_PARSING_FAILED,

        // Generic failure code for all other errors.
        EBPF_FAILED,

        // Operation is not supported.
        EBPF_OPERATION_NOT_SUPPORTED,

        // The requested key was not found.
        EBPF_KEY_NOT_FOUND,

        // Access was denied for the requested operation.
        EBPF_ACCESS_DENIED,

        // The operation was blocked for all requesters by policy.
        EBPF_BLOCKED_BY_POLICY,

        // Arithmetic overflow occurred.
        EBPF_ARITHMETIC_OVERFLOW,

        // The eBPF extension failed to load.
        EBPF_EXTENSION_FAILED_TO_LOAD,

        // A buffer of insufficient size was supplied.
        EBPF_INSUFFICIENT_BUFFER,

        // The enumeration found no more keys.
        EBPF_NO_MORE_KEYS,
    } ebpf_result_t;

#ifdef __cplusplus
}
#endif
