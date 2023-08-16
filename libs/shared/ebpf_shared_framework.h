// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include "shared_context.h"

#include <specstrings.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define EBPF_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))
#define EBPF_FROM_FIELD(s, m, o) (s*)((uint8_t*)o - EBPF_OFFSET_OF(s, m))

#define EBPF_DEVICE_NAME L"\\Device\\EbpfIoDevice"
#define EBPF_SYMBOLIC_DEVICE_NAME L"\\GLOBAL??\\EbpfIoDevice"
#define EBPF_DEVICE_WIN32_NAME L"\\\\.\\EbpfIoDevice"

    /**
     * @brief Duplicate a string.
     * @param[in] size Size of memory to allocate.
     * @returns Pointer to memory block allocated, or null on failure.
     */
    _Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_allocate(size_t size);

    /**
     * @brief Allocate memory.
     * @param[in] size Size of memory to allocate.
     * @param[in] tag Pool tag to use.
     * @returns Pointer to memory block allocated, or null on failure.
     */
    _Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_allocate_with_tag(size_t size, uint32_t tag);

    /**
     * @brief Reallocate memory.
     * @param[in] memory Allocation to be reallocated.
     * @param[in] old_size Old size of memory to reallocate.
     * @param[in] new_size New size of memory to reallocate.
     * @returns Pointer to memory block allocated, or null on failure.
     */
    _Must_inspect_result_ _Ret_writes_maybenull_(new_size) void* ebpf_reallocate(
        _In_ _Post_invalid_ void* memory, size_t old_size, size_t new_size);

    /**
     * @brief Free memory.
     * @param[in] memory Allocation to be freed.
     */
    void
    ebpf_free(_Frees_ptr_opt_ void* memory);

    /**
     * @brief Duplicate a null-terminated string.
     *
     * @param[in] source String to duplicate.
     * @return Pointer to the duplicated string or NULL if out of memory.
     */
    _Must_inspect_result_ char*
    ebpf_duplicate_string(_In_z_ const char* source);

#ifdef __cplusplus
}
#endif
