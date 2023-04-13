// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_base.h"
#include "ebpf_result.h"

#include <guiddef.h>
#include <stdint.h>

#define EBPF_MAX_PROGRAM_DESCRIPTOR_NAME_LENGTH 256
#define EBPF_MAX_HELPER_FUNCTION_NAME_LENGTH 256

typedef struct _ebpf_program_type_descriptor
{
    const char* name;
    const ebpf_context_descriptor_t* context_descriptor;
    GUID program_type;
    uint32_t bpf_prog_type;
    char is_privileged;
} ebpf_program_type_descriptor_t;

typedef struct _ebpf_helper_function_prototype
{
    uint32_t helper_id;
    const char* name;
    ebpf_return_type_t return_type;
    ebpf_argument_type_t arguments[5];
} ebpf_helper_function_prototype_t;

typedef struct _ebpf_program_info
{
    ebpf_program_type_descriptor_t program_type_descriptor;
    uint32_t count_of_program_type_specific_helpers;
    const ebpf_helper_function_prototype_t* program_type_specific_helper_prototype;
    uint32_t count_of_global_helpers;
    const ebpf_helper_function_prototype_t* global_helper_prototype;
} ebpf_program_info_t;

typedef struct _ebpf_helper_function_addresses
{
    uint32_t helper_function_count;
    uint64_t* helper_function_address;
} ebpf_helper_function_addresses_t;

typedef ebpf_result_t (*ebpf_program_context_create_t)(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

typedef void (*ebpf_program_context_destroy_t)(
    _In_ void* context,
    _Out_writes_bytes_to_opt_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_opt_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

typedef struct _ebpf_program_data
{
    const ebpf_program_info_t* program_info; ///< Pointer to program information.
    const ebpf_helper_function_addresses_t*
        program_type_specific_helper_function_addresses; ///< Pointer to program type specific helper function
                                                         ///< addresses.
    const ebpf_helper_function_addresses_t*
        global_helper_function_addresses;           ///< Pointer to global helper function addresses being overriden.
    ebpf_program_context_create_t context_create;   ///< Pointer to context create function.
    ebpf_program_context_destroy_t context_destroy; ///< Pointer to context destroy function.
    uint8_t required_irql;                          ///< IRQL at which the program is invoked.
} ebpf_program_data_t;

typedef struct _ebpf_program_section_info
{
    const wchar_t* section_name;
    const GUID* program_type;
    const GUID* attach_type;
    uint32_t bpf_program_type;
    uint32_t bpf_attach_type;
} ebpf_program_section_info_t;
