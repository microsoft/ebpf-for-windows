/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "pch.h"
#include <stdio.h>
#include "rpc_interface_h.h"
#include "ebpf_windows.h"
#include "Verifier.h"

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
    const char* path = nullptr;
    const char* section_name = nullptr;

    // Verify the program
    retVal = verify_byte_code2(
        path,
        section_name,
        reinterpret_cast<const GUID*>(&info->program_type),
        reinterpret_cast<uint8_t*>(info->instructions),
        info->instruction_count * sizeof(uint64_t),
        (const char**)logs);
    /*
    if (verify_byte_code(nullptr, nullptr, reinterpret_cast<uint8_t *>instructions byte_code.data(), byte_code_size,
    error_message) != 0) { return ERROR_INVALID_PARAMETER;
    }
    */
    // *log_size =
    if (retVal != 0) {
        result = EBPF_VALIDATION_FAILED;
    }

    return result;
}
