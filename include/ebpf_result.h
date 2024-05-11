/*
 *  Copyright (c) eBPF for Windows contributors
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
        /// The operation was successful.
        EBPF_SUCCESS, // = 0

        /// Program verification failed.
        EBPF_VERIFICATION_FAILED,

        /// JIT compilation failed.
        EBPF_JIT_COMPILATION_FAILED,

        /// Program load failed.
        EBPF_PROGRAM_LOAD_FAILED,

        /// Invalid FD provided.
        EBPF_INVALID_FD,

        /// Invalid object provided (ebpf_object, ebpf_map, ebpf_program).
        EBPF_INVALID_OBJECT, // = 5

        /// An invalid argument was supplied.
        EBPF_INVALID_ARGUMENT,

        /// No pinned map or program exists for the path provided.
        EBPF_OBJECT_NOT_FOUND,

        /// A program or map is already pinned with the same path.
        EBPF_OBJECT_ALREADY_EXISTS,

        /// Invalid ELF file path.
        EBPF_FILE_NOT_FOUND,

        /// The program or map already pinned to a different path.
        EBPF_ALREADY_PINNED, // = 10

        /// The program or map is not pinned.
        EBPF_NOT_PINNED,

        /// Low memory.
        EBPF_NO_MEMORY,

        /// The program is too large.
        EBPF_PROGRAM_TOO_LARGE,

        /// An RPC exception occurred.
        EBPF_RPC_EXCEPTION,

        /// The handle was already initialized.
        EBPF_ALREADY_INITIALIZED, // = 15

        /// A failure occurred in parsing the ELF file.
        EBPF_ELF_PARSING_FAILED,

        /// Generic failure code for all other errors.
        EBPF_FAILED,

        /// Operation is not supported.
        EBPF_OPERATION_NOT_SUPPORTED,

        /// The requested key was not found.
        EBPF_KEY_NOT_FOUND,

        /// Access was denied for the requested operation.
        EBPF_ACCESS_DENIED, // = 20

        /// The operation was blocked for all requesters by policy.
        EBPF_BLOCKED_BY_POLICY,

        /// Arithmetic overflow occurred.
        EBPF_ARITHMETIC_OVERFLOW,

        /// The eBPF extension failed to load.
        EBPF_EXTENSION_FAILED_TO_LOAD,

        /// A buffer of insufficient size was supplied.
        EBPF_INSUFFICIENT_BUFFER,

        /// The enumeration found no more keys.
        EBPF_NO_MORE_KEYS, // = 25

        /// The requested key is already present.
        EBPF_KEY_ALREADY_EXISTS,

        /// Caller has reached tail call limit.
        EBPF_NO_MORE_TAIL_CALLS,

        /// Requested action is still pending.
        EBPF_PENDING,

        /// The container can not hold additional elements.
        EBPF_OUT_OF_SPACE,

        /// Operation was canceled.
        EBPF_CANCELED, // = 30

        /// Invalid pointer.
        EBPF_INVALID_POINTER,

        /// Operation timed out.
        EBPF_TIMEOUT,

        /// ID is valid, but the object has been deleted.
        EBPF_STALE_ID,

        /// The system is in an invalid state for this operation.
        EBPF_INVALID_STATE,

        /// The operation should be retried.
        EBPF_TRY_AGAIN, // = 35
    } ebpf_result_t;

#define EBPF_RESULT_COUNT (EBPF_TRY_AGAIN + 1)

#ifdef __cplusplus
}
#endif
