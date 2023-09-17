// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include "cxplat.h"
#include "ebpf_result.h"
#include "shared_context.h"

#include <specstrings.h>
#include <stdint.h>

CXPLAT_EXTERN_C_BEGIN

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
    EBPF_POOL_TAG_RANDOM = 'gnre',
    EBPF_POOL_TAG_RING_BUFFER = 'fbre',
    EBPF_POOL_TAG_STATE = 'atse',
} ebpf_pool_tag_t;

/**
 * @brief Allocate memory.
 * @deprecated Use ebpf_allocate_with_tag() instead.
 * @param[in] size Size of memory to allocate.
 * @param[in] tag Pool tag to use.
 * @returns Pointer to zero-initialized memory block allocated, or null on failure.
 */
__forceinline __drv_allocatesMem(Mem) _Must_inspect_result_
    _Ret_writes_maybenull_(size) void* ebpf_allocate(size_t size)
{
    return cxplat_allocate(CXPLAT_POOL_FLAG_NON_PAGED, size, EBPF_POOL_TAG_DEFAULT);
}

__forceinline void
ebpf_free(_Frees_ptr_opt_ void* pointer)
{
    cxplat_free(pointer, CXPLAT_POOL_FLAG_NON_PAGED, 0);
}

#define ebpf_reallocate cxplat_reallocate

/**
 * @brief Allocate memory.
 * @param[in] size Size of memory to allocate.
 * @param[in] tag Pool tag to use.
 * @returns Pointer to zero-initialized memory block allocated, or null on failure.
 */
__forceinline __drv_allocatesMem(Mem) _Must_inspect_result_
    _Ret_writes_maybenull_(size) void* ebpf_allocate_with_tag(size_t size, uint32_t tag)
{
    return cxplat_allocate(CXPLAT_POOL_FLAG_NON_PAGED, size, tag);
}

#define ebpf_safe_size_t_add(augend, addend, result) \
    ebpf_result_from_cxplat_status(cxplat_safe_size_t_add(augend, addend, result))
#define ebpf_safe_size_t_subtract(minuend, subtrahend, result) \
    ebpf_result_from_cxplat_status(cxplat_safe_size_t_subtract(minuend, subtrahend, result))
#define ebpf_safe_size_t_multiply(multiplicand, multiplier, result) \
    ebpf_result_from_cxplat_status(cxplat_safe_size_t_multiply(multiplicand, multiplier, result))

ebpf_result_t
ebpf_result_from_cxplat_status(cxplat_status_t status);

CXPLAT_EXTERN_C_END
