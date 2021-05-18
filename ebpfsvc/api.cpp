/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "pch.h"
#include <stdio.h>
#include "rpc_interface_h.h"
#include "ebpf_windows.h"
#include "Verifier.h"

void
cache_map_file_descriptors(const EbpfMapDescriptor* map_descriptors, uint32_t map_descriptors_count);

void
clear_map_descriptors();

ebpf_result_t
ebpf_verify_and_jit_program(
    /* [in] */ ebpf_program_load_info* info,
    /* [out] */ uint32_t* logs_size,
    /* [size_is][size_is][out] */ unsigned char** logs)
{
    UNREFERENCED_PARAMETER(info);
    UNREFERENCED_PARAMETER(logs_size);
    UNREFERENCED_PARAMETER(logs);

    return EBPF_FAILED;
}

ebpf_result_t
ebpf_verify_program(
    /* [in] */ ebpf_program_verify_info* info,
    /* [out] */ uint32_t* logs_size,
    /* [size_is][size_is][out] */ unsigned char** logs)
{
    UNREFERENCED_PARAMETER(info);
    UNREFERENCED_PARAMETER(logs_size);
    UNREFERENCED_PARAMETER(logs);

    const char* report;
    const char* error_message;
    ebpf_result_t result = EBPF_SUCCESS;
    int retVal = 0;
    const char* path = "";
    const char* section_name = "";

    // Validate input
    if (info == nullptr || info->byte_code_size == 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    clear_map_descriptors();

    cache_map_file_descriptors(reinterpret_cast<EbpfMapDescriptor*>(info->map_descriptors), info->map_count);

    // Verify the program
    retVal = verify_byte_code2(
        path,
        section_name,
        reinterpret_cast<const GUID*>(&info->program_type),
        info->byte_code,
        info->byte_code_size,
        (const char**)logs);

    if (retVal != 0) {
        result = EBPF_VALIDATION_FAILED;
    }

    return result;
}
