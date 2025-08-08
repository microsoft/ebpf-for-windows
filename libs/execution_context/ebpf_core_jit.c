// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_core.h"
#include "ebpf_core_jit.h"
#include "ebpf_maps.h"
#include "ebpf_program.h"
#include "ebpf_serialize.h"
#include "ebpf_tracelog.h"

// Forward declarations for external functions.
extern _Must_inspect_result_ ebpf_result_t
ebpf_program_create_and_initialize(
    _In_ const ebpf_program_parameters_t* parameters, _Out_ ebpf_handle_t* program_handle);

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
_Must_inspect_result_ ebpf_result_t
ebpf_core_protocol_load_code(_In_ const ebpf_operation_load_code_request_t* request)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    uint8_t* code = NULL;
    size_t code_length = 0;

    if (request->code_type <= EBPF_CODE_NONE || request->code_type >= EBPF_CODE_MAX) {
        retval = EBPF_INVALID_ARGUMENT;
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_CORE, "load_code: Invalid code type", request->code_type);
        goto Done;
    }

    if (request->code_type == EBPF_CODE_NATIVE) {
        retval = EBPF_INVALID_ARGUMENT;
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_CORE,
            "code_type == EBPF_CODE_NATIVE can only be loaded through program driver");
        goto Done;
    }

    if (request->code_type == EBPF_CODE_JIT) {
        if (_ebpf_platform_hypervisor_code_integrity_enabled) {
            retval = EBPF_BLOCKED_BY_POLICY;
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_CORE,
                "code_type == EBPF_CODE_JIT blocked by Hyper-V Code Integrity policy");
            goto Done;
        }
    }

    retval = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(ebpf_operation_load_code_request_t, code), &code_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    code = (uint8_t*)request->code;

    retval = ebpf_core_load_code(request->program_handle, request->code_type, NULL, code, code_length);

Done:
    EBPF_RETURN_RESULT(retval);
}

_Must_inspect_result_ ebpf_result_t
ebpf_core_protocol_create_program(
    _In_ const ebpf_operation_create_program_request_t* request, _Inout_ ebpf_operation_create_program_reply_t* reply)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_program_parameters_t parameters = {0};
    uint8_t* file_name = NULL;
    size_t file_name_length = 0;
    uint8_t* section_name = NULL;
    size_t section_name_length = 0;
    uint8_t* program_name = NULL;
    size_t program_name_length = 0;

    // Valid if:
    // offsetof(data) <= section_name_offset <= program_name_offset <= header.length
    if ((EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data) > request->section_name_offset) ||
        (request->section_name_offset > request->program_name_offset) ||
        (request->program_name_offset > request->header.length)) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }
    file_name = (uint8_t*)request->data;
    section_name = ((uint8_t*)request) + request->section_name_offset;
    program_name = ((uint8_t*)request) + request->program_name_offset;
    file_name_length = section_name - file_name;
    section_name_length = program_name - section_name;
    program_name_length = ((uint8_t*)request) + request->header.length - program_name;

    parameters.program_type = request->program_type;
    parameters.program_name.value = program_name;
    parameters.program_name.length = program_name_length;
    parameters.section_name.value = section_name;
    parameters.section_name.length = section_name_length;
    parameters.file_name.value = file_name;
    parameters.file_name.length = file_name_length;

    retval = ebpf_program_create_and_initialize(&parameters, &reply->program_handle);

Done:
    EBPF_RETURN_RESULT(retval);
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
_Must_inspect_result_ ebpf_result_t
ebpf_core_protocol_resolve_helper(
    _In_ const ebpf_operation_resolve_helper_request_t* request,
    _Inout_ ebpf_operation_resolve_helper_reply_t* reply,
    uint16_t reply_length)
{
    EBPF_LOG_ENTRY();
    uint32_t* request_helper_ids = NULL;
    size_t required_reply_length = 0;
    size_t helper_id_length;
    ebpf_result_t return_value = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id), &helper_id_length);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }
    size_t count_of_helpers = helper_id_length / sizeof(request->helper_id[0]);
    required_reply_length =
        EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + count_of_helpers * sizeof(reply->address[0]);
    size_t helper_index;

    if (reply_length < required_reply_length) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (count_of_helpers != 0) {
        request_helper_ids = (uint32_t*)ebpf_allocate_with_tag(count_of_helpers * sizeof(uint32_t), EBPF_POOL_TAG_CORE);
        if (request_helper_ids == NULL) {
            return_value = EBPF_NO_MEMORY;
            goto Done;
        }
        for (helper_index = 0; helper_index < count_of_helpers; helper_index++) {
            request_helper_ids[helper_index] = request->helper_id[helper_index];
        }
    }

    return_value =
        ebpf_core_resolve_helper(request->program_handle, count_of_helpers, request_helper_ids, reply->address);

Done:
    if (return_value == EBPF_SUCCESS) {
        reply->header.length = (uint16_t)required_reply_length;
    }

    ebpf_free(request_helper_ids);
    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_core_protocol_resolve_map(
    _In_ const struct _ebpf_operation_resolve_map_request* request,
    _Inout_ struct _ebpf_operation_resolve_map_reply* reply,
    uint16_t reply_length)
{
    EBPF_LOG_ENTRY();
    size_t map_handle_length;
    ebpf_result_t return_value = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(ebpf_operation_resolve_map_request_t, map_handle), &map_handle_length);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }
    uint32_t count_of_maps = (uint32_t)(map_handle_length / sizeof(request->map_handle[0]));
    size_t required_reply_length =
        EBPF_OFFSET_OF(ebpf_operation_resolve_map_reply_t, address) + count_of_maps * sizeof(reply->address[0]);

    if (reply_length < required_reply_length) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (count_of_maps == 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    return_value = ebpf_core_resolve_maps(request->program_handle, count_of_maps, request->map_handle, reply->address);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    reply->header.length = (uint16_t)required_reply_length;

Done:
    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ uint64_t
ebpf_core_protocol_get_ec_function(
    _In_ const ebpf_operation_get_ec_function_request_t* request, _Inout_ ebpf_operation_get_ec_function_reply_t* reply)
{
    EBPF_LOG_ENTRY();
    if (request->function != EBPF_EC_FUNCTION_LOG) {
        return EBPF_INVALID_ARGUMENT;
    }

    reply->address = (uint64_t)ebpf_log_function;
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}
#endif