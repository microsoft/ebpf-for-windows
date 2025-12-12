// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief Sample eBPF Extension program types.
 */

#include "ebpf_program_attach_type_guids.h" // TODO(issue #2305): remove this include.
#include "ebpf_structs.h"
#include "sample_ext_helpers.h"

#define SAMPLE_EXT_HELPER_FUNCTION_START EBPF_MAX_GENERAL_HELPER_FUNCTION

#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))

static const ebpf_context_descriptor_t _sample_ebpf_context_descriptor = {
    sizeof(sample_program_context_t),
    EBPF_OFFSET_OF(sample_program_context_t, data_start),
    EBPF_OFFSET_OF(sample_program_context_t, data_end),
    -1};

// Sample Extension Helper function prototype descriptors.
static const ebpf_helper_function_prototype_t _sample_ebpf_extension_helper_function_prototype[] = {
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     SAMPLE_EXT_HELPER_FUNCTION_START + 1,
     "sample_ebpf_extension_helper_function1",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX}},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     SAMPLE_EXT_HELPER_FUNCTION_START + 2,
     "sample_ebpf_extension_find",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE}},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     SAMPLE_EXT_HELPER_FUNCTION_START + 3,
     "sample_ebpf_extension_replace",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_ANYTHING,
      EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE}},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     SAMPLE_EXT_HELPER_FUNCTION_START + 4,
     "sample_ebpf_extension_helper_implicit_1",
     EBPF_RETURN_TYPE_INTEGER,
     {0},
     {0},
     true},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     SAMPLE_EXT_HELPER_FUNCTION_START + 5,
     "sample_ebpf_extension_helper_implicit_2",
     EBPF_RETURN_TYPE_INTEGER,
     {0},
     {0},
     true},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     SAMPLE_EXT_HELPER_FUNCTION_START + 6,
     "sample_ext_helper_map_lookup_element",
     EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY},
     {0},
     true}};

// Global helper function prototype descriptors.
static const ebpf_helper_function_prototype_t _sample_ebpf_extension_global_helper_function_prototype[] = {
    {
        EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
        BPF_FUNC_get_current_pid_tgid,
        "bpf_get_current_pid_tgid",
        EBPF_RETURN_TYPE_INTEGER,
    },
};

static const ebpf_program_type_descriptor_t _sample_ebpf_extension_program_type_descriptor = {
    EBPF_PROGRAM_TYPE_DESCRIPTOR_HEADER,
    "sample",
    &_sample_ebpf_context_descriptor,
    EBPF_PROGRAM_TYPE_SAMPLE_GUID,
    BPF_PROG_TYPE_SAMPLE};
static const ebpf_program_info_t _sample_ebpf_extension_program_info = {
    EBPF_PROGRAM_INFORMATION_HEADER,
    &_sample_ebpf_extension_program_type_descriptor,
    EBPF_COUNT_OF(_sample_ebpf_extension_helper_function_prototype),
    _sample_ebpf_extension_helper_function_prototype,
    EBPF_COUNT_OF(_sample_ebpf_extension_global_helper_function_prototype),
    _sample_ebpf_extension_global_helper_function_prototype};
