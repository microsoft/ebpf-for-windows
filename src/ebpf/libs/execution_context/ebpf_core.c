/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_core.h"

#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_maps.h"
#include "ebpf_pinning_table.h"
#include "ebpf_program.h"

static ebpf_pinning_table_t* _ebpf_core_map_pinning_table = NULL;

static ebpf_lock_t _ebpf_core_hook_table_lock = {0};
static ebpf_program_t* _ebpf_core_hook_table[EBPF_PROGRAM_TYPE_BIND + 1] = {0};

// Assume enabled until we can query it
static ebpf_code_integrity_state_t _ebpf_core_code_integrity_state = EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE;

static void*
_ebpf_core_map_find_element(ebpf_map_t* map, const uint8_t* key);
static void
_ebpf_core_map_update_element(ebpf_map_t* map, const uint8_t* key, const uint8_t* data);
static void
_ebpf_core_map_delete_element(ebpf_map_t* map, const uint8_t* key);

static uint64_t
ebpf_core_interpreter_helper_resolver(void* context, uint32_t helper_id);

static const void* _ebpf_program_helpers[] = {
    NULL,
    (void*)&_ebpf_core_map_find_element,
    (void*)&_ebpf_core_map_update_element,
    (void*)&_ebpf_core_map_delete_element};

size_t
ebpf_core_get_global_helper_count()
{
    return EBPF_COUNT_OF(_ebpf_program_helpers);
}

const void*
ebpf_core_get_global_helper(size_t helper_id)
{
    return _ebpf_program_helpers[helper_id];
}

static ebpf_error_code_t
_ebpf_core_set_hook_entry(ebpf_program_t* code, ebpf_program_type_t program_type)
{
    ebpf_lock_state_t state;
    if (program_type > EBPF_PROGRAM_TYPE_BIND || program_type <= EBPF_PROGRAM_TYPE_UNSPECIFIED) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }
    ebpf_lock_lock(&_ebpf_core_hook_table_lock, &state);
    if (_ebpf_core_hook_table[program_type])
        ebpf_object_release_reference((ebpf_object_t*)_ebpf_core_hook_table[program_type]);
    _ebpf_core_hook_table[program_type] = code;
    if (_ebpf_core_hook_table[program_type])
        ebpf_object_acquire_reference((ebpf_object_t*)_ebpf_core_hook_table[program_type]);
    ebpf_lock_unlock(&_ebpf_core_hook_table_lock, &state);
    return EBPF_ERROR_SUCCESS;
}

static ebpf_program_t*
_ebpf_core_get_hook_entry(ebpf_program_type_t program_type)
{
    ebpf_program_t* code = NULL;
    ebpf_lock_state_t state;
    if (program_type > EBPF_PROGRAM_TYPE_BIND || program_type <= EBPF_PROGRAM_TYPE_UNSPECIFIED) {
        return NULL;
    }
    ebpf_lock_lock(&_ebpf_core_hook_table_lock, &state);
    code = _ebpf_core_hook_table[program_type];
    ebpf_lock_unlock(&_ebpf_core_hook_table_lock, &state);
    return code;
}

ebpf_error_code_t
ebpf_core_initiate()
{
    ebpf_error_code_t return_value;

    return_value = ebpf_platform_initiate();
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    return_value = ebpf_epoch_initiate();
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    return_value = ebpf_pinning_table_allocate(&_ebpf_core_map_pinning_table);
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    return_value = ebpf_handle_table_initiate();
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    ebpf_lock_create(&_ebpf_core_hook_table_lock);

    return_value = ebpf_get_code_integrity_state(&_ebpf_core_code_integrity_state);

Done:
    if (return_value != EBPF_ERROR_SUCCESS) {
        ebpf_epoch_terminate();
        ebpf_platform_terminate();
        ebpf_handle_table_terminate();
    }
    return return_value;
}

void
ebpf_core_terminate()
{
    ebpf_handle_table_terminate();

    ebpf_pinning_table_free(_ebpf_core_map_pinning_table);

    ebpf_epoch_terminate();

    ebpf_platform_terminate();
}

static ebpf_error_code_t
_ebpf_core_protocol_attach_code(_In_ const struct _ebpf_operation_attach_detach_request* request)
{
    ebpf_error_code_t retval = EBPF_ERROR_NOT_FOUND;
    ebpf_program_t* program = NULL;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    switch (request->hook) {
    case EBPF_PROGRAM_TYPE_XDP:
    case EBPF_PROGRAM_TYPE_BIND:
        break;
    default:
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    _ebpf_core_set_hook_entry(program, request->hook);
    retval = EBPF_ERROR_SUCCESS;

Done:
    ebpf_object_release_reference((ebpf_object_t*)program);
    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_detach_code(_In_ const struct _ebpf_operation_attach_detach_request* request)
{
    ebpf_error_code_t retval = EBPF_ERROR_NOT_FOUND;
    ebpf_program_t* program = NULL;
    ebpf_program_parameters_t parameters;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    retval = ebpf_program_get_properties(program, &parameters);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    _ebpf_core_set_hook_entry(NULL, parameters.program_type);

    retval = EBPF_ERROR_SUCCESS;

Done:
    ebpf_object_release_reference((ebpf_object_t*)program);

    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_unload_code(_In_ const struct _ebpf_operation_unload_code_request* request)
{
    ebpf_handle_close(request->handle);
    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t
_ebpf_core_protocol_load_code(
    _In_ const ebpf_operation_load_code_request_t* request,
    _Inout_ struct _ebpf_operation_load_code_reply* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    ebpf_program_t* program = NULL;
    uint8_t* file_name = NULL;
    size_t file_name_length = 0;
    uint8_t* section_name = NULL;
    size_t section_name_length = 0;
    uint8_t* code = NULL;
    size_t code_length = 0;
    ebpf_program_parameters_t parameters;

    UNREFERENCED_PARAMETER(reply_length);

    if (request->file_name_offset > request->header.length) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    if (request->section_name_offset > request->header.length) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    if (request->code_offset > request->header.length) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    if (request->code_type == EBPF_CODE_NATIVE) {
        if (_ebpf_core_code_integrity_state == EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE) {
            retval = EBPF_ERROR_BLOCKED_BY_POLICY;
            goto Done;
        }
    }

    retval = ebpf_program_create(&program);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    file_name = (uint8_t*)request + request->file_name_offset;
    section_name = (uint8_t*)request + request->section_name_offset;
    code = (uint8_t*)request + request->code_offset;
    file_name_length = section_name - file_name;
    section_name_length = code - section_name;
    code_length = request->header.length - request->code_offset;

    parameters.program_name.value = file_name;
    parameters.program_name.length = file_name_length;
    parameters.section_name.value = section_name;
    parameters.section_name.length = section_name_length;

    retval = ebpf_program_initialize(program, &parameters);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    if (request->code_type == EBPF_CODE_NATIVE) {
        retval = ebpf_program_load_machine_code(program, code, code_length);
    } else {
        retval =
            ebpf_program_load_byte_code(program, (ebpf_instuction_t*)code, code_length / sizeof(ebpf_instuction_t));
    }

    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    retval = ebpf_handle_create(&reply->handle, (ebpf_object_t*)program);

Done:
    ebpf_object_release_reference((ebpf_object_t*)program);
    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_resolve_helper(
    _In_ const struct _ebpf_operation_resolve_helper_request* request,
    _Inout_ struct _ebpf_operation_resolve_helper_reply* reply,
    uint16_t reply_length)
{
    size_t count_of_helpers =
        (request->header.length - EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id)) /
        sizeof(request->helper_id[0]);
    size_t required_reply_length =
        EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + count_of_helpers * sizeof(reply->address[0]);
    size_t helper_index;

    if (reply_length < required_reply_length) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    for (helper_index = 0; helper_index < count_of_helpers; helper_index++) {
        if (request->helper_id[helper_index] >= EBPF_COUNT_OF(_ebpf_program_helpers)) {
            return EBPF_ERROR_INVALID_PARAMETER;
        }
        reply->address[helper_index] = (uint64_t)_ebpf_program_helpers[request->helper_id[helper_index]];
    }
    reply->header.length = (uint16_t)required_reply_length;

    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t
_ebpf_core_protocol_resolve_map(
    _In_ const struct _ebpf_operation_resolve_map_request* request,
    _Inout_ struct _ebpf_operation_resolve_map_reply* reply,
    uint16_t reply_length)
{
    size_t count_of_maps = (request->header.length - EBPF_OFFSET_OF(ebpf_operation_resolve_map_request_t, map_handle)) /
                           sizeof(request->map_handle[0]);
    size_t required_reply_length =
        EBPF_OFFSET_OF(ebpf_operation_resolve_map_reply_t, address) + count_of_maps * sizeof(reply->address[0]);
    size_t map_index;
    ebpf_error_code_t return_value;

    if (reply_length < required_reply_length) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    for (map_index = 0; map_index < count_of_maps; map_index++) {
        ebpf_map_t* map;
        return_value =
            ebpf_reference_object_by_handle(request->map_handle[map_index], EBPF_OBJECT_MAP, (ebpf_object_t**)&map);

        if (return_value != EBPF_ERROR_SUCCESS)
            goto Done;

        ebpf_object_release_reference((ebpf_object_t*)map);

        reply->address[map_index] = (uint64_t)map;
    }
    reply->header.length = (uint16_t)required_reply_length;
    return_value = EBPF_ERROR_SUCCESS;

Done:
    return return_value;
}

ebpf_error_code_t
ebpf_core_invoke_hook(ebpf_program_type_t hook_point, _Inout_ void* context, _Inout_ uint32_t* result)
{
    ebpf_error_code_t retval;
    ebpf_program_t* program = NULL;

    retval = ebpf_epoch_enter();
    if (retval != EBPF_ERROR_SUCCESS)
        return retval;

    program = _ebpf_core_get_hook_entry(hook_point);
    if (program) {
        ebpf_program_invoke(program, context, result);
    }

    ebpf_epoch_exit();
    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t
_ebpf_core_protocol_create_map(
    _In_ const struct _ebpf_operation_create_map_request* request,
    _Inout_ struct _ebpf_operation_create_map_reply* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    ebpf_map_t* map = NULL;
    UNREFERENCED_PARAMETER(reply_length);

    retval = ebpf_map_create(&request->ebpf_map_definition, &map);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    retval = ebpf_handle_create(&reply->handle, (ebpf_object_t*)map);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    retval = EBPF_ERROR_SUCCESS;

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);

    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_map_find_element(
    _In_ const ebpf_operation_map_find_element_request_t* request,
    _Inout_ ebpf_operation_map_find_element_reply_t* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    ebpf_map_t* map = NULL;
    uint8_t* value = NULL;
    ebpf_map_definition_t* map_definition;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    map_definition = ebpf_map_get_definition(map);

    if (request->header.length <
        (EBPF_OFFSET_OF(ebpf_operation_map_find_element_request_t, key) + map_definition->key_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    if (reply_length < (EBPF_OFFSET_OF(ebpf_operation_map_find_element_reply_t, value) + map_definition->value_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    value = ebpf_map_find_entry(map, request->key);
    if (value == NULL) {
        retval = EBPF_ERROR_NOT_FOUND;
        goto Done;
    }

    memcpy(reply->value, value, map_definition->value_size);
    retval = EBPF_ERROR_SUCCESS;

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);
    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_map_update_element(_In_ const epf_operation_map_update_element_request_t* request)
{
    ebpf_error_code_t retval;
    ebpf_map_t* map = NULL;
    ebpf_map_definition_t* map_definition;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    map_definition = ebpf_map_get_definition(map);

    if (request->header.length < (EBPF_OFFSET_OF(epf_operation_map_update_element_request_t, data) +
                                  map_definition->key_size + map_definition->value_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    retval = ebpf_map_update_entry(map, request->data, request->data + map_definition->key_size);

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);
    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_map_delete_element(_In_ const ebpf_operation_map_delete_element_request_t* request)
{
    ebpf_error_code_t retval;
    ebpf_map_t* map = NULL;
    ebpf_map_definition_t* map_definition;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    map_definition = ebpf_map_get_definition(map);

    if (request->header.length <
        (EBPF_OFFSET_OF(ebpf_operation_map_delete_element_request_t, key) + map_definition->key_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    retval = ebpf_map_delete_entry(map, request->key);

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);
    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_map_get_next_key(
    _In_ const ebpf_operation_map_get_next_key_request_t* request,
    _Inout_ ebpf_operation_map_get_next_key_reply_t* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    ebpf_map_t* map = NULL;
    ebpf_map_definition_t* map_definition;
    const uint8_t* previous_key;
    uint8_t* next_key = NULL;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    map_definition = ebpf_map_get_definition(map);

    // If request length shows zero key, treat as restart.
    if (request->header.length == EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key)) {
        previous_key = NULL;
    } else if (
        request->header.length <
        (EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key) + map_definition->key_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    } else {
        previous_key = request->previous_key;
    }

    next_key = reply->next_key;
    if (reply_length < (EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_reply_t, next_key) + map_definition->key_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    retval = ebpf_map_next_key(map, previous_key, next_key);

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);

    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_get_next_map(
    _In_ const struct _ebpf_operation_get_next_map_request* request,
    _Inout_ struct _ebpf_operation_get_next_map_reply* reply,
    uint16_t reply_length)
{
    UNREFERENCED_PARAMETER(reply_length);

    return ebpf_get_next_handle_by_type(request->previous_handle, EBPF_OBJECT_MAP, &reply->next_handle);
}

static ebpf_error_code_t
_ebpf_core_protocol_get_next_program(
    _In_ const struct _ebpf_operation_get_next_program_request* request,
    _Inout_ struct _ebpf_operation_get_next_program_reply* reply,
    uint16_t reply_length)
{
    UNREFERENCED_PARAMETER(reply_length);

    return ebpf_get_next_handle_by_type(request->previous_handle, EBPF_OBJECT_PROGRAM, &reply->next_handle);
}

static ebpf_error_code_t
_ebpf_core_protocol_query_map_definition(
    _In_ const struct _ebpf_operation_query_map_definition_request* request,
    _Inout_ struct _ebpf_operation_query_map_definition_reply* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    ebpf_map_t* map = NULL;
    UNREFERENCED_PARAMETER(reply_length);

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    reply->map_definition = *ebpf_map_get_definition(map);
    retval = EBPF_ERROR_SUCCESS;

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);

    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_query_program_information(
    _In_ const struct _ebpf_operation_query_program_information_request* request,
    _Inout_ struct _ebpf_operation_query_program_information_reply* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    ebpf_program_t* program = NULL;
    size_t required_reply_length;
    ebpf_program_parameters_t parameters;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    retval = ebpf_program_get_properties(program, &parameters);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    required_reply_length = EBPF_OFFSET_OF(struct _ebpf_operation_query_program_information_reply, data) +
                            parameters.program_name.length + parameters.section_name.length;

    if (reply_length < required_reply_length) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    reply->file_name_offset = EBPF_OFFSET_OF(struct _ebpf_operation_query_program_information_reply, data);
    reply->section_name_offset = reply->file_name_offset + (uint16_t)parameters.program_name.length;

    memcpy(reply->data, parameters.program_name.value, parameters.program_name.length);
    memcpy(reply->data + parameters.program_name.length, parameters.section_name.value, parameters.section_name.length);
    reply->code_type = parameters.code_type;

    reply->header.length = (uint16_t)required_reply_length;

Done:
    ebpf_object_release_reference((ebpf_object_t*)program);

    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_update_map_pinning(_In_ const struct _ebpf_operation_update_map_pinning_request* request)
{
    ebpf_error_code_t retval;
    const ebpf_utf8_string_t name = {
        (uint8_t*)request->name,
        request->header.length - EBPF_OFFSET_OF(ebpf_operation_update_map_pinning_request_t, name)};
    ebpf_map_t* map = NULL;

    if (name.length == 0) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    if (request->handle == UINT64_MAX) {
        retval = ebpf_pinning_table_delete(_ebpf_core_map_pinning_table, &name);
        goto Done;
    } else {
        retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
        if (retval != EBPF_ERROR_SUCCESS)
            goto Done;

        retval = ebpf_pinning_table_insert(_ebpf_core_map_pinning_table, &name, (ebpf_object_t*)map);
    }
Done:
    ebpf_object_release_reference((ebpf_object_t*)map);

    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_get_pinned_map(
    _In_ const struct _ebpf_operation_get_map_pinning_request* request,
    _Inout_ struct _ebpf_operation_get_map_pinning_reply* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    ebpf_map_t* map = NULL;
    const ebpf_utf8_string_t name = {
        (uint8_t*)request->name,
        request->header.length - EBPF_OFFSET_OF(ebpf_operation_get_map_pinning_request_t, name)};
    UNREFERENCED_PARAMETER(reply_length);

    if (name.length == 0) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    retval = ebpf_pinning_table_find(_ebpf_core_map_pinning_table, &name, (ebpf_object_t**)&map);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    retval = ebpf_handle_create(&reply->handle, (ebpf_object_t*)map);

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);
    return retval;
}

static void*
_ebpf_core_map_find_element(ebpf_map_t* map, const uint8_t* key)
{
    return ebpf_map_find_entry(map, key);
}

static void
_ebpf_core_map_update_element(ebpf_map_t* map, const uint8_t* key, const uint8_t* value)
{
    ebpf_map_update_entry(map, key, value);
}

static void
_ebpf_core_map_delete_element(ebpf_map_t* map, const uint8_t* key)
{
    ebpf_map_delete_entry(map, key);
}

static uint64_t
ebpf_core_interpreter_helper_resolver(void* context, uint32_t helper_id)
{
    UNREFERENCED_PARAMETER(context);
    if (helper_id >= EBPF_COUNT_OF(_ebpf_program_helpers)) {
        return 0;
    }
    return (uint64_t)_ebpf_program_helpers[helper_id];
}

typedef struct _ebpf_protocol_handler
{
    union
    {
        ebpf_error_code_t (*protocol_handler_no_reply)(_In_ const void* input_buffer);
        ebpf_error_code_t (*protocol_handler_with_reply)(
            _In_ const void* input_buffer,
            _Out_writes_bytes_(output_buffer_length) void* output_buffer,
            uint16_t output_buffer_length);
    } dispatch;
    size_t minimum_request_size;
    size_t minimum_reply_size;
} const ebpf_protocol_handler_t;

static ebpf_protocol_handler_t _ebpf_protocol_handlers[EBPF_OPERATION_GET_MAP_PINNING + 1] = {
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_resolve_helper,
     sizeof(struct _ebpf_operation_resolve_helper_request),
     sizeof(struct _ebpf_operation_resolve_helper_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_resolve_map,
     sizeof(struct _ebpf_operation_resolve_map_request),
     sizeof(struct _ebpf_operation_resolve_map_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_load_code,
     sizeof(struct _ebpf_operation_load_code_request),
     sizeof(struct _ebpf_operation_load_code_reply)},
    {_ebpf_core_protocol_unload_code, sizeof(struct _ebpf_operation_unload_code_request), 0},
    {_ebpf_core_protocol_attach_code, sizeof(struct _ebpf_operation_attach_detach_request), 0},
    {_ebpf_core_protocol_detach_code, sizeof(struct _ebpf_operation_attach_detach_request), 0},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_create_map,
     sizeof(struct _ebpf_operation_create_map_request),
     sizeof(struct _ebpf_operation_create_map_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_map_find_element,
     sizeof(struct _ebpf_operation_map_find_element_request),
     sizeof(struct _ebpf_operation_map_find_element_reply)},
    {_ebpf_core_protocol_map_update_element, sizeof(struct _ebpf_operation_map_update_element_request), 0},
    {_ebpf_core_protocol_map_delete_element, sizeof(struct _ebpf_operation_map_delete_element_request), 0},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_map_get_next_key,
     EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key),
     sizeof(ebpf_operation_map_get_next_key_reply_t)},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_get_next_map,
     sizeof(struct _ebpf_operation_get_next_map_request),
     sizeof(struct _ebpf_operation_get_next_map_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_get_next_program,
     sizeof(struct _ebpf_operation_get_next_program_request),
     sizeof(struct _ebpf_operation_get_next_program_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_query_map_definition,
     sizeof(struct _ebpf_operation_query_map_definition_request),
     sizeof(struct _ebpf_operation_query_map_definition_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_query_program_information,
     sizeof(struct _ebpf_operation_query_program_information_request),
     sizeof(struct _ebpf_operation_query_program_information_reply)},
    {_ebpf_core_protocol_update_map_pinning, sizeof(struct _ebpf_operation_update_map_pinning_request), 0},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_get_pinned_map,
     sizeof(struct _ebpf_operation_get_map_pinning_request),
     sizeof(struct _ebpf_operation_get_map_pinning_reply)},
};

ebpf_error_code_t
ebpf_core_get_protocol_handler_properties(
    ebpf_operation_id_t operation_id, _Out_ size_t* minimum_request_size, _Out_ size_t* minimum_reply_size)
{
    *minimum_request_size = 0;
    *minimum_reply_size = 0;

    if (operation_id > EBPF_OPERATION_GET_MAP_PINNING || operation_id < EBPF_OPERATION_RESOLVE_HELPER)
        return EBPF_ERROR_NOT_SUPPORTED;

    if (!_ebpf_protocol_handlers[operation_id].dispatch.protocol_handler_no_reply)
        return EBPF_ERROR_NOT_SUPPORTED;

    *minimum_request_size = _ebpf_protocol_handlers[operation_id].minimum_request_size;
    *minimum_reply_size = _ebpf_protocol_handlers[operation_id].minimum_reply_size;
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_core_invoke_protocol_handler(
    ebpf_operation_id_t operation_id,
    _In_ const void* input_buffer,
    _Out_writes_bytes_(output_buffer_length) void* output_buffer,
    uint16_t output_buffer_length)
{
    ebpf_error_code_t retval;

    if (operation_id > EBPF_OPERATION_GET_MAP_PINNING || operation_id < EBPF_OPERATION_RESOLVE_HELPER) {
        return EBPF_ERROR_NOT_SUPPORTED;
    }

    retval = ebpf_epoch_enter();
    if (retval != EBPF_ERROR_SUCCESS)
        return retval;

    if (output_buffer == NULL)
        retval = _ebpf_protocol_handlers[operation_id].dispatch.protocol_handler_no_reply(input_buffer);
    else
        retval = _ebpf_protocol_handlers[operation_id].dispatch.protocol_handler_with_reply(
            input_buffer, output_buffer, output_buffer_length);

    ebpf_epoch_exit();
    return retval;
}
