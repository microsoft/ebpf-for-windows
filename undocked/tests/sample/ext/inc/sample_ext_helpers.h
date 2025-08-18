// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief This file contains program context and helper functions declarations that are
 * exposed by the sample extension.
 */

#if !defined(NO_CRT) && !defined(_NO_CRT_STDIO_INLINE)
#include <stdint.h>
#else
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;
#endif

// Sample extension program context.
typedef struct _sample_program_context
{
    uint8_t* data_start;
    uint8_t* data_end;
    uint32_t uint32_data;
    uint16_t uint16_data;
    uint32_t helper_data_1;
    uint32_t helper_data_2;
} sample_program_context_t;

#define SAMPLE_EXT_HELPER_FN_BASE 0xFFFF

#ifndef __doxygen
#define EBPF_HELPER(return_type, name, args) typedef return_type(*const name##_t) args
#endif

/**
 * @brief Illustrates helper function with parameter of type EBPF_ARGUMENT_TYPE_PTR_TO_CTX.
 * @param[in] context Pointer to program context.
 * @retval 0 The operation was successful.
 */
EBPF_HELPER(int64_t, sample_ebpf_extension_helper_function1, (sample_program_context_t * context));
#ifndef __doxygen
#define sample_ebpf_extension_helper_function1 ((sample_ebpf_extension_helper_function1_t)SAMPLE_EXT_HELPER_FN_BASE + 1)
#endif

/**
 * @brief Looks for the supplied pattern in the input buffer.
 * @param[in] context Pointer to buffer.
 * @param[in] size Size of buffer.
 * @param[in] find Pointer to pattern buffer.
 * @param[in] arg_size Length of pattern buffer.
 * @returns Offset of the input buffer where the patter begins.
 */
EBPF_HELPER(int64_t, sample_ebpf_extension_find, (void* buffer, size_t size, void* find, size_t arg_size));
#ifndef __doxygen
#define sample_ebpf_extension_find ((sample_ebpf_extension_find_t)SAMPLE_EXT_HELPER_FN_BASE + 2)
#endif

/**
 * @brief Replaces bytes in input buffer with supplied replacement at given offset.
 * @param[in] context Pointer to buffer.
 * @param[in] size Size of buffer.
 * @param[in] position Offset of input buffer at which replacement has to be done.
 * @param[in] find Pointer to replacement buffer.
 * @param[in] arg_size Length of replacement buffer.
 * @retval 0 The operation was successful.
 * @retval -1 An error occurred.
 */
EBPF_HELPER(
    int64_t,
    sample_ebpf_extension_replace,
    (void* buffer, size_t size, int64_t position, void* replace, size_t arg_size));
#ifndef __doxygen
#define sample_ebpf_extension_replace ((sample_ebpf_extension_replace_t)SAMPLE_EXT_HELPER_FN_BASE + 3)
#endif

/**
 * @brief Replaces bytes in input buffer with supplied replacement at given offset.
 * @param[in] context Pointer to buffer.
 * @param[in] size Size of buffer.
 * @param[in] position Offset of input buffer at which replacement has to be done.
 * @param[in] find Pointer to replacement buffer.
 * @param[in] arg_size Length of replacement buffer.
 * @retval 0 The operation was successful.
 * @retval -1 An error occurred.
 */
EBPF_HELPER(int64_t, sample_ebpf_extension_helper_implicit_1, ());
#ifndef __doxygen
#define sample_ebpf_extension_helper_implicit_1 \
    ((sample_ebpf_extension_helper_implicit_1_t)SAMPLE_EXT_HELPER_FN_BASE + 4)
#endif

/**
 * @brief Replaces bytes in input buffer with supplied replacement at given offset.
 * @param[in] context Pointer to buffer.
 * @param[in] size Size of buffer.
 * @param[in] position Offset of input buffer at which replacement has to be done.
 * @param[in] find Pointer to replacement buffer.
 * @param[in] arg_size Length of replacement buffer.
 * @retval 0 The operation was successful.
 * @retval -1 An error occurred.
 */
EBPF_HELPER(int64_t, sample_ebpf_extension_helper_implicit_2, (uint32_t arg));
#ifndef __doxygen
#define sample_ebpf_extension_helper_implicit_2 \
    ((sample_ebpf_extension_helper_implicit_2_t)SAMPLE_EXT_HELPER_FN_BASE + 5)
#endif
