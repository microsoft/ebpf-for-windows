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
    ebpf_core_invoke_hook(_In_ ebpf_program_type_t hook_point, _Inout_ void* context, _Inout_ uint32_t* result);

    typedef struct _ebpf_protocol_handler
    {
        union
        {
            ebpf_error_code_t (*protocol_handler_no_reply)(_In_ const void* input_buffer);
            ebpf_error_code_t (*protocol_handler_with_reply)(
                _In_ const void* input_buffer, void* output_buffer, uint16_t output_buffer_length);
        } dispatch;
        size_t minimum_request_size;
        size_t minimum_reply_size;
    } const ebpf_protocol_handler_t;

    extern ebpf_protocol_handler_t EbpfProtocolHandlers[EBPF_OPERATION_LOOKUP_MAP_PINNING + 1];

#ifdef __cplusplus
}
#endif
