/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

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
    ebpf_core_protocol_attach_code(_In_ const struct _ebpf_operation_attach_detach_request* request);

    ebpf_error_code_t
    ebpf_core_protocol_detach_code(_In_ const struct _ebpf_operation_attach_detach_request* request);

    ebpf_error_code_t
    ebpf_core_protocol_unload_code(_In_ const struct _ebpf_operation_unload_code_request* request);

    ebpf_error_code_t
    ebpf_core_protocol_load_code(
        _In_ const struct _ebpf_operation_load_code_request* inputRequest,
        _Inout_ struct _ebpf_operation_load_code_reply* loadReply,
        uint16_t reply_length);

    ebpf_error_code_t
    ebpf_core_protocol_resolve_helper(
        _In_ const struct _ebpf_operation_resolve_helper_request* request,
        _Inout_ struct _ebpf_operation_resolve_helper_reply* reply,
        uint16_t reply_length);

    ebpf_error_code_t
    ebpf_core_protocol_resolve_map(
        _In_ const struct _ebpf_operation_resolve_map_request* request,
        _Inout_ struct _ebpf_operation_resolve_map_reply* reply,
        uint16_t reply_length);

    ebpf_error_code_t
    ebpf_core_protocol_create_map(
        _In_ const struct _ebpf_operation_create_map_request* request,
        _Inout_ struct _ebpf_operation_create_map_reply* reply,
        uint16_t reply_length);

    ebpf_error_code_t
    ebpf_core_protocol_map_lookup_element(
        _In_ const struct _ebpf_operation_map_lookup_element_request* request,
        _Inout_ struct _ebpf_operation_map_lookup_element_reply* reply,
        uint16_t reply_length);

    ebpf_error_code_t
    ebpf_core_protocol_map_update_element(_In_ const struct _ebpf_operation_map_update_element_request* request);

    ebpf_error_code_t
    ebpf_core_protocol_map_delete_element(_In_ const struct _ebpf_operation_map_delete_element_request* request);

    ebpf_error_code_t
    ebpf_core_protocol_map_get_next_key(
        _In_ const struct _ebpf_operation_map_next_key_request* request,
        _Inout_ struct _ebpf_operation_map_next_key_reply* reply,
        uint16_t reply_length);

    ebpf_error_code_t
    ebpf_core_protocol_enumerate_maps(
        _In_ const struct _ebpf_operation_enumerate_maps_request* request,
        _Inout_ struct _ebpf_operation_enumerate_maps_reply* reply,
        uint16_t reply_length);

    ebpf_error_code_t
    ebpf_core_protocol_query_map_definition(
        _In_ const struct _ebpf_operation_query_map_definition_request* request,
        _Inout_ struct _ebpf_operation_query_map_definition_reply* reply,
        uint16_t reply_length);

    ebpf_error_code_t
    ebpf_core_protocol_update_map_pinning(_In_ const struct _ebpf_operation_update_map_pinning_request* request);

    ebpf_error_code_t
    ebpf_core_protocol_lookup_map_pinning(
        _In_ const struct _ebpf_operation_lookup_map_pinning_request* request,
        _Inout_ struct _ebpf_operation_lookup_map_pinning_reply* reply,
        uint16_t reply_length);

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
