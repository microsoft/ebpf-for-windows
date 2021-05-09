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
        EBPF_SUCCESS,

        // Program verification failed.
        EBPF_VALIDATION_FAILED,

        // Program load failed.
        EBPF_LOAD_FAILED,

        // Invalid FD provided.
        EBPF_INVALID_FD,

        // Invalid object provided (ebpf_object, ebpf_map, ebpf_program)
        EBPF_INVALID_OBJECT,

        EBPF_INVALID_ARGUMENT,

        // No pinned map or program exists for the path provided.
        EBPF_OBJECT_NOT_FOUND,

        // A program or map is already pinned with the same path.
        EBPF_OBJECT_ALREADY_EXISTS,

        // Invalid ELF file path
        EBPF_FILE_NOT_FOUND,

        // Program or map already pinned.
        EBPF_ALREADY_PINNED,

        // Program or map is not pinned.
        EBPF_NOT_PINNED,

        // Map key not found.
        EBPF_MAP_KEY_NOT_FOUND,

        // Low memory.
        EBPF_NO_MEMORY,

        // Generic failure code for all other errors.
        EBPF_FAILED,
    } ebpf_result_t;

#ifdef __cplusplus
}
#endif
