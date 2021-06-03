/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum ebpf_result
    {
        // The operation was successful.
        EBPF_SUCCESS,

        // Program verification failed.
        EBPF_VALIDATION_FAILED,

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

        // Program or map already pinned.
        EBPF_ALREADY_PINNED,

        // Program or map is not pinned.
        EBPF_NOT_PINNED,

        // Low memory.
        EBPF_NO_MEMORY,

        // The program is too large.
        EBPF_PROGRAM_TOO_LARGE,

        // Generic failure code for all other errors.
        EBPF_FAILED,

        // Operation is not supported.
        EBPF_ERROR_NOT_SUPPORTED,

        // The requested item was not found.
        EBPF_ERROR_NOT_FOUND,

        // Access was denied for the requested operation.
        EBPF_ERROR_ACCESS_DENIED,

        // The operation was blocked by policy.
        EBPF_ERROR_BLOCKED_BY_POLICY,

        // Arithmetic overflow occurred.
        EBPF_ERROR_ARITHMETIC_OVERFLOW,

        // The eBPF extension failed to load.
        EBPF_ERROR_EXTENSION_FAILED_TO_LOAD,

        // A buffer of insufficient size was supplied.
        EBPF_ERROR_INSUFFICIENT_BUFFER,

        // The enumeration found no more keys.
        EBPF_ERROR_NO_MORE_KEYS,

        // The handle was invalid.
        EBPF_ERROR_INVALID_HANDLE,
    } ebpf_result_t;

#ifdef __cplusplus
}
#endif
