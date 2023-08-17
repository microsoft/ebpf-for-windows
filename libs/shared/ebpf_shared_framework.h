// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include "ebpf_result.h"
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

#define EBPF_CACHE_LINE_SIZE 64
#define EBPF_CACHE_ALIGN_POINTER(P) (void*)(((uintptr_t)P + EBPF_CACHE_LINE_SIZE - 1) & ~(EBPF_CACHE_LINE_SIZE - 1))
#define EBPF_PAD_CACHE(X) ((X + EBPF_CACHE_LINE_SIZE - 1) & ~(EBPF_CACHE_LINE_SIZE - 1))
#define EBPF_PAD_8(X) ((X + 7) & ~7)

#define EBPF_DEVICE_NAME L"\\Device\\EbpfIoDevice"
#define EBPF_SYMBOLIC_DEVICE_NAME L"\\GLOBAL??\\EbpfIoDevice"
#define EBPF_DEVICE_WIN32_NAME L"\\\\.\\EbpfIoDevice"

// Macro locally suppresses "Unreferenced variable" warning, which in 'Release' builds is treated as an error.
#define ebpf_assert_success(x)                                     \
    _Pragma("warning(push)") _Pragma("warning(disable : 4189)") do \
    {                                                              \
        ebpf_result_t _result = (x);                               \
        ebpf_assert(_result == EBPF_SUCCESS && #x);                \
    }                                                              \
    while (0)                                                      \
    _Pragma("warning(pop)")

    typedef enum _ebpf_pool_tag
    {
        EBPF_POOL_TAG_ASYNC = 'nsae',
        EBPF_POOL_TAG_CORE = 'roce',
        EBPF_POOL_TAG_DEFAULT = 'fpbe',
        EBPF_POOL_TAG_EPOCH = 'cpee',
        EBPF_POOL_TAG_LINK = 'knle',
        EBPF_POOL_TAG_MAP = 'pame',
        EBPF_POOL_TAG_NATIVE = 'vtne',
        EBPF_POOL_TAG_PROGRAM = 'grpe',
        EBPF_POOL_TAG_RING_BUFFER = 'fbre',
        EBPF_POOL_TAG_STATE = 'atse',
    } ebpf_pool_tag_t;

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
     * TODO: ebpf_strdup() and this seem to be duplicates.
     *
     * @param[in] source String to duplicate.
     * @return Pointer to the duplicated string or NULL if out of memory.
     */
    _Must_inspect_result_ _Ret_maybenull_z_ char*
    ebpf_duplicate_string(_In_z_ const char* source);

    /**
     * @brief Allocate memory.
     * @param[in] source String to duplicate.
     * @returns Pointer to duplicated string, or null on failure.
     */
    _Must_inspect_result_ _Ret_maybenull_z_ char*
    ebpf_strdup(_In_z_ const char* source);

    /**
     * @brief Multiplies one value of type size_t by another and check for
     *   overflow.
     * @param[in] multiplicand The value to be multiplied by multiplier.
     * @param[in] multiplier The value by which to multiply multiplicand.
     * @param[out] result A pointer to the result.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_ARITHMETIC_OVERFLOW Multiplication overflowed.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_safe_size_t_multiply(
        size_t multiplicand, size_t multiplier, _Out_ _Deref_out_range_(==, multiplicand* multiplier) size_t* result);

    /**
     * @brief Add one value of type size_t by another and check for
     *   overflow.
     * @param[in] augend The value to be added by addend.
     * @param[in] addend The value add to augend.
     * @param[out] result A pointer to the result.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_ARITHMETIC_OVERFLOW Addition overflowed.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_safe_size_t_add(size_t augend, size_t addend, _Out_ _Deref_out_range_(==, augend + addend) size_t* result);

    /**
     * @brief Subtract one value of type size_t from another and check for
     *   overflow or underflow.
     * @param[in] minuend The value from which subtrahend is subtracted.
     * @param[in] subtrahend The value subtract from minuend.
     * @param[out] result A pointer to the result.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_ARITHMETIC_OVERFLOW Addition overflowed or underflowed.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_safe_size_t_subtract(
        size_t minuend, size_t subtrahend, _Out_ _Deref_out_range_(==, minuend - subtrahend) size_t* result);

#ifdef __cplusplus
}
#endif
