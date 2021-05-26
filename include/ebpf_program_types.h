/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#ifdef __midl
#define MIDL(x) x
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#else
#define MIDL(x)
#include <guiddef.h>
#include <stdint.h>
#endif

typedef enum _ebpf_helper_return_type
{
    EBPF_RETURN_TYPE_INTEGER = 0,
    EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    EBPF_RETURN_TYPE_VOID,
} ebpf_helper_return_type_t;

typedef enum _ebpf_helper_argument_type
{
    EBPF_ARGUMENT_TYPE_DONTCARE = 0,
    EBPF_ARGUMENT_TYPE_ANYTHING, // All values are valid, e.g., 64-bit flags.
    EBPF_ARGUMENT_TYPE_CONST_SIZE,
    EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE,
    EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
    EBPF_ARGUMENT_TYPE_PTR_TO_MEM_OR_NULL,
    EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
} ebpf_helper_argument_type_t;

typedef struct _ebpf_context_descriptor
{
    int size; // Size of ctx struct.
    int data; // Offset into ctx struct of pointer to data.
    int end;  // Offset into ctx struct of pointer to end of data.
    int meta; // Offset into ctx struct of pointer to metadata.
} ebpf_context_descriptor_t;

typedef struct _ebpf_program_type_descriptor
{
    MIDL([string])
    const char* name;
    ebpf_context_descriptor_t* context_descriptor;
    GUID platform_specific_data;
    char is_privileged;
} ebpf_program_type_descriptor_t;

typedef struct _ebpf_helper_function_prototype
{
    uint32_t helper_id;
    MIDL([string])
    const char* name;
    ebpf_helper_return_type_t return_type;
    ebpf_helper_argument_type_t arguments[5];
} ebpf_helper_function_prototype_t;

typedef struct _ebpf_program_information
{
    ebpf_program_type_descriptor_t program_type_descriptor;
    uint32_t count_of_helpers;
    MIDL([size_is(count_of_helpers)]) ebpf_helper_function_prototype_t* helper_prototype;
} ebpf_program_information_t;