/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include "ebpf_platform.h"
#include "ebpf_protocol.h"

#ifdef __cplusplus
extern "C"
{
#endif
#include "ebpf_protocol.h"

    typedef uint32_t(__stdcall* ebpf_hook_function)(uint8_t*);
    ebpf_error_code_t
    ebpf_core_initialize();

    void
    ebpf_core_terminate();

    ebpf_error_code_t
    ebpf_core_invoke_hook(ebpf_program_type_t hook_point, _Inout_ void* context, _Inout_ uint32_t* result);

    ebpf_error_code_t
    ebpf_core_invoke_protocol_handler(
        ebpf_operation_id_t operation_id,
        _In_ const void* input_buffer,
        _Out_writes_bytes_(output_buffer_length) void* output_buffer,
        uint16_t output_buffer_length);

    ebpf_error_code_t
    ebpf_core_get_protocol_handler_properties(
        ebpf_operation_id_t operation_id, _Out_ size_t* minimum_request_size, _Out_ size_t* minimum_reply_size);

#ifdef __cplusplus
}
#endif
