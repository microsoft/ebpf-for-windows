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
#include "ebpf_base.h"

#define EBPF_MAX_PROGRAM_DESCRIPTOR_NAME_LENGTH 256
#define EBPF_MAX_HELPER_FUNCTION_NAME_LENGTH 256

typedef struct _ebpf_program_type_descriptor
{
    MIDL([string])
    const char* name;
    ebpf_context_descriptor_t* context_descriptor;
    GUID program_type;
    uint32_t bpf_prog_type;
    char is_privileged;
} ebpf_program_type_descriptor_t;

typedef struct _ebpf_helper_function_prototype
{
    uint32_t helper_id;
    MIDL([string])
    const char* name;
    ebpf_return_type_t return_type;
    ebpf_argument_type_t arguments[5];
} ebpf_helper_function_prototype_t;

typedef struct _ebpf_program_info
{
    ebpf_program_type_descriptor_t program_type_descriptor;
    uint32_t count_of_program_type_specific_helpers;
    MIDL([size_is(count_of_program_type_specific_helpers)])
    ebpf_helper_function_prototype_t* program_type_specific_helper_prototype;
    uint32_t count_of_global_helpers;
    MIDL([size_is(count_of_global_helpers)]) ebpf_helper_function_prototype_t* global_helper_prototype;
} ebpf_program_info_t;

typedef struct _ebpf_helper_function_addresses
{
    uint32_t helper_function_count;
    MIDL([size_is(helper_function_count)]) uint64_t* helper_function_address;
} ebpf_helper_function_addresses_t;

typedef struct _ebpf_program_data
{
    ebpf_program_info_t* program_info;
    ebpf_helper_function_addresses_t* program_type_specific_helper_function_addresses;
    ebpf_helper_function_addresses_t* global_helper_function_addresses;
} ebpf_program_data_t;

typedef struct _ebpf_program_section_info
{
    const wchar_t* section_name;
    GUID* program_type;
    GUID* attach_type;
    uint32_t bpf_program_type;
    uint32_t bpf_attach_type;
} ebpf_program_section_info_t;