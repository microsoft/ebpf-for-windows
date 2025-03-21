// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once
#include "cxplat.h"
#include "ebpf_extension.h"
#include "ebpf_program_types.h"
#include "ebpf_result.h"
#include "ebpf_windows.h"
#include "shared_context.h"

#include <specstrings.h>
#include <stdint.h>

CXPLAT_EXTERN_C_BEGIN

#define ARRAY_ELEMENT_INDEX(array, index, element_size) (((uint8_t*)array) + (index * element_size));

#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define EBPF_FROM_FIELD(s, m, o) (s*)((uint8_t*)o - EBPF_OFFSET_OF(s, m))

#define EBPF_CACHE_LINE_SIZE 64
#define EBPF_CACHE_ALIGN_POINTER(P) (void*)(((uintptr_t)P + EBPF_CACHE_LINE_SIZE - 1) & ~(EBPF_CACHE_LINE_SIZE - 1))
#define EBPF_PAD_CACHE(X) ((X + EBPF_CACHE_LINE_SIZE - 1) & ~(EBPF_CACHE_LINE_SIZE - 1))
#define EBPF_PAD_8(X) ((X + 7) & ~7)

#define EBPF_DEVICE_NAME L"\\Device\\EbpfIoDevice"
#define EBPF_SYMBOLIC_DEVICE_NAME L"\\GLOBAL??\\EbpfIoDevice"
#define EBPF_DEVICE_WIN32_NAME L"\\\\.\\EbpfIoDevice"

#define ebpf_assert_assume(x) \
    ebpf_assert(x);           \
    __analysis_assume(x);

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

__forceinline void
ebpf_free_cache_aligned(_Frees_ptr_opt_ void* pointer)
{
    cxplat_free(pointer, (cxplat_pool_flags_t)(CXPLAT_POOL_FLAG_NON_PAGED | CXPLAT_POOL_FLAG_CACHE_ALIGNED), 0);
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

__forceinline __drv_allocatesMem(Mem) _Must_inspect_result_
    _Ret_writes_maybenull_(size) void* ebpf_allocate_cache_aligned_with_tag(size_t size, uint32_t tag)
{
    return cxplat_allocate(
        (cxplat_pool_flags_t)(CXPLAT_POOL_FLAG_NON_PAGED | CXPLAT_POOL_FLAG_CACHE_ALIGNED), size, tag);
}

#define ebpf_safe_size_t_add(augend, addend, result) \
    ebpf_result_from_cxplat_status(cxplat_safe_size_t_add(augend, addend, result))
#define ebpf_safe_size_t_subtract(minuend, subtrahend, result) \
    ebpf_result_from_cxplat_status(cxplat_safe_size_t_subtract(minuend, subtrahend, result))
#define ebpf_safe_size_t_multiply(multiplicand, multiplier, result) \
    ebpf_result_from_cxplat_status(cxplat_safe_size_t_multiply(multiplicand, multiplier, result))

ebpf_result_t
ebpf_result_from_cxplat_status(cxplat_status_t status);

bool
ebpf_validate_attach_provider_data(_In_ const ebpf_attach_provider_data_t* attach_provider_data);

bool
ebpf_validate_program_data(_In_ const ebpf_program_data_t* program_data);

bool
ebpf_validate_program_section_info(_In_ const ebpf_program_section_info_t* section_info);

bool
ebpf_validate_program_info(_In_ const ebpf_program_info_t* program_info);

bool
ebpf_validate_helper_function_prototype_array(
    _In_reads_(count) const ebpf_helper_function_prototype_t* helper_prototype, uint32_t count);

/**
 * @brief Validate the extension header for native module helper function entry.
 * @param[in] native_helper_function_entry_header Pointer to extension header for
 *            native helper function entry.

 * @returns true if validation succeeds, false otherwise.
 */
bool
ebpf_validate_object_header_native_helper_function_entry(
    _In_ const ebpf_extension_header_t* native_helper_function_entry_header);

/**
 * @brief Validate the extension header for native module map entry structure.
 * @param[in] native_map_entry_header Pointer to extension header for native map entry.

 * @returns true if validation succeeds, false otherwise.
 */
bool
ebpf_validate_object_header_native_map_entry(_In_ const ebpf_extension_header_t* native_map_entry_header);

/**
 * @brief Validate the extension header for native module program entry structure.
 * @param[in] native_program_entry_header Pointer to extension header for native program entry.

 * @returns true if validation succeeds, false otherwise.
 */
bool
ebpf_validate_object_header_native_program_entry(_In_ const ebpf_extension_header_t* native_program_entry_header);

/**
 * @brief Validate the extension header for native map initial values structure.
 * @param[in] native_map_initial_values_header Pointer to extension header for native map
 *            initial values structure.

 * @returns true if validation succeeds, false otherwise.
 */
bool
ebpf_validate_object_header_native_map_initial_values(
    _In_ const ebpf_extension_header_t* native_map_initial_values_header);

/**
 * @brief Validate the extension header for native global variable section info structure.
 * @param[in] native_global_variable_section_info_header Pointer to extension header for
 *            global variable section info structure

 * @returns true if validation succeeds, false otherwise.
 */
bool
ebpf_validate_object_header_native_global_variable_section_info(
    _In_ const ebpf_extension_header_t* native_global_variable_section_info_header);

/**
 * @brief Helper Function to free ebpf_program_info_t.
 *
 * @param[in] program_info Program info to be freed.
 */
void
ebpf_program_info_free(_In_opt_ _Post_invalid_ ebpf_program_info_t* program_info);

/**
 * @brief Helper Function to duplicate ebpf_program_info_t to the latest version with safe defaults.
 *
 * @param[in] info Program info to be duplicated.
 * @param[out] new_info Duplicated program info.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Out of memory.
 */
ebpf_result_t
ebpf_duplicate_program_info(_In_ const ebpf_program_info_t* info, _Outptr_ ebpf_program_info_t** new_info);

/**
 * @brief Helper Function to free ebpf_program_data_t.
 *
 * @param[in] program_data Program data to be freed.
 */
void
ebpf_program_data_free(_In_opt_ ebpf_program_data_t* program_data);

/**
 * @brief Helper Function to duplicate ebpf_program_data_t to the latest version with safe defaults.
 *
 * @param[in] program_data Program data to be duplicated.
 * @param[out] new_program_data Duplicated program data.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Out of memory.
 */
ebpf_result_t
ebpf_duplicate_program_data(
    _In_ const ebpf_program_data_t* program_data, _Outptr_ ebpf_program_data_t** new_program_data);

CXPLAT_EXTERN_C_END
