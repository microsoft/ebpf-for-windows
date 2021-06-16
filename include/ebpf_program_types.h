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
#include "../external/ebpf-verifier/src/ebpf_base.h"

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
    ebpf_return_type_t return_type;
    ebpf_argument_type_t arguments[5];
} ebpf_helper_function_prototype_t;

typedef struct _ebpf_program_information
{
    ebpf_program_type_descriptor_t program_type_descriptor;
    uint32_t count_of_helpers;
    MIDL([size_is(count_of_helpers)]) ebpf_helper_function_prototype_t* helper_prototype;
} ebpf_program_information_t;