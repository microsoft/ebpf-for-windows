/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_core.h"

#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_maps.h"
#include "ebpf_pinning_table.h"
#include "ebpf_program.h"

GUID ebpf_global_helper_function_interface_id = {/* 8d2a1d3f-9ce6-473d-b48e-17aa5c5581fe */
                                                 0x8d2a1d3f,
                                                 0x9ce6,
                                                 0x473d,
                                                 {0xb4, 0x8e, 0x17, 0xaa, 0x5c, 0x55, 0x81, 0xfe}};

static ebpf_extension_dispatch_table_t* _ebpf_global_helper_function_dispatch_table = NULL;
static ebpf_extension_provider_t* _ebpf_global_helper_function_provider_context = NULL;

static ebpf_pinning_table_t* _ebpf_core_map_pinning_table = NULL;

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

    ebpf_object_tracking_initiate();

    return_value = ebpf_pinning_table_allocate(&_ebpf_core_map_pinning_table);
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    return_value = ebpf_handle_table_initiate();
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    _ebpf_global_helper_function_dispatch_table = ebpf_allocate(
        EBPF_OFFSET_OF(ebpf_extension_dispatch_table_t, function) + sizeof(_ebpf_program_helpers),
        EBPF_MEMORY_NO_EXECUTE);
    if (!_ebpf_global_helper_function_dispatch_table) {
        return_value = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }

    _ebpf_global_helper_function_dispatch_table->version = 0;
    _ebpf_global_helper_function_dispatch_table->size =
        EBPF_OFFSET_OF(ebpf_extension_dispatch_table_t, function) + sizeof(_ebpf_program_helpers);

    memcpy(_ebpf_global_helper_function_dispatch_table->function, _ebpf_program_helpers, sizeof(_ebpf_program_helpers));

    return_value = ebpf_provider_load(
        &_ebpf_global_helper_function_provider_context,
        &ebpf_global_helper_function_interface_id,
        NULL,
        NULL,
        _ebpf_global_helper_function_dispatch_table,
        NULL,
        NULL,
        NULL);

    if (return_value != EBPF_ERROR_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_get_code_integrity_state(&_ebpf_core_code_integrity_state);

Done:
    if (return_value != EBPF_ERROR_SUCCESS) {
        ebpf_core_terminate();
    }
    return return_value;
}

void
ebpf_core_terminate()
{
    ebpf_provider_unload(_ebpf_global_helper_function_provider_context);
    _ebpf_global_helper_function_provider_context = NULL;

    ebpf_free(_ebpf_global_helper_function_dispatch_table);
    _ebpf_global_helper_function_dispatch_table = NULL;

    ebpf_handle_table_terminate();

    ebpf_pinning_table_free(_ebpf_core_map_pinning_table);

    ebpf_object_tracking_terminate();

    ebpf_epoch_terminate();

    ebpf_platform_terminate();
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
_ebpf_core_get_next_handle(ebpf_handle_t previous_handle, ebpf_object_type_t type, ebpf_handle_t* next_handle)
{
    ebpf_error_code_t retval;
    ebpf_object_t* previous_object = NULL;
    ebpf_object_t* next_object = NULL;

    if (previous_handle != UINT64_MAX) {
        retval = ebpf_reference_object_by_handle(previous_handle, type, (ebpf_object_t**)&previous_object);
        if (retval != EBPF_ERROR_SUCCESS)
            goto Done;
    }

    ebpf_object_reference_next_object(previous_object, type, &next_object);

    if (next_object)
        retval = ebpf_handle_create(next_handle, next_object);
    else
        *next_handle = UINT64_MAX;

    retval = EBPF_ERROR_SUCCESS;

Done:
    ebpf_object_release_reference(previous_object);
    ebpf_object_release_reference(next_object);

    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_get_next_map(
    _In_ const struct _ebpf_operation_get_next_map_request* request,
    _Inout_ struct _ebpf_operation_get_next_map_reply* reply,
    uint16_t reply_length)
{
    UNREFERENCED_PARAMETER(reply_length);
    return _ebpf_core_get_next_handle(request->previous_handle, EBPF_OBJECT_MAP, &reply->next_handle);
}

static ebpf_error_code_t
_ebpf_core_protocol_get_next_program(
    _In_ const struct _ebpf_operation_get_next_program_request* request,
    _Inout_ struct _ebpf_operation_get_next_program_reply* reply,
    uint16_t reply_length)
{
    UNREFERENCED_PARAMETER(reply_length);
    return _ebpf_core_get_next_handle(request->previous_handle, EBPF_OBJECT_PROGRAM, &reply->next_handle);
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

static ebpf_error_code_t
_ebpf_core_protocol_link_program(
    _In_ const ebpf_operation_link_program_request_t* request, _Inout_ ebpf_operation_link_program_reply_t* reply)
{
    ebpf_error_code_t retval;
    ebpf_program_t* program = NULL;
    ebpf_link_t* link = NULL;

    retval = ebpf_reference_object_by_handle(request->program_handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    retval = ebpf_link_create(&link);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    retval = ebpf_link_initialize(link, request->attach_type, NULL, 0);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    retval = ebpf_link_attach_program(link, program);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

    retval = ebpf_handle_create(&reply->link_handle, (ebpf_object_t*)link);
    if (retval != EBPF_ERROR_SUCCESS)
        goto Done;

Done:
    ebpf_object_release_reference((ebpf_object_t*)program);
    ebpf_object_release_reference((ebpf_object_t*)link);
    return retval;
}

static ebpf_error_code_t
_ebpf_core_protocol_close_handle(_In_ const ebpf_operation_close_handle_request_t* request)
{
    return ebpf_handle_close(request->handle);
}

static uint64_t
_ebpf_core_protocol_get_ec_function(
    _In_ const ebpf_operation_get_ec_function_request_t* request, _Inout_ ebpf_operation_get_ec_function_reply_t* reply)
{
    if (request->function != EBPF_EC_FUNCTION_LOG)
        return EBPF_ERROR_INVALID_PARAMETER;

    reply->address = (uint64_t)ebpf_log_function;
    return EBPF_ERROR_SUCCESS;
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

static ebpf_protocol_handler_t _ebpf_protocol_handlers[EBPF_OPERATION_GET_EC_FUNCTION + 1] = {
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_resolve_helper,
     sizeof(struct _ebpf_operation_resolve_helper_request),
     sizeof(struct _ebpf_operation_resolve_helper_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_resolve_map,
     sizeof(struct _ebpf_operation_resolve_map_request),
     sizeof(struct _ebpf_operation_resolve_map_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_load_code,
     sizeof(struct _ebpf_operation_load_code_request),
     sizeof(struct _ebpf_operation_load_code_reply)},
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
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_link_program,
     sizeof(ebpf_operation_link_program_request_t),
     sizeof(ebpf_operation_link_program_reply_t)},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_close_handle,
     sizeof(ebpf_operation_close_handle_request_t),
     0},
    {(ebpf_error_code_t(__cdecl*)(const void*))_ebpf_core_protocol_get_ec_function,
     sizeof(ebpf_operation_get_ec_function_request_t),
     sizeof(ebpf_operation_get_ec_function_reply_t)}};

ebpf_error_code_t
ebpf_core_get_protocol_handler_properties(
    ebpf_operation_id_t operation_id, _Out_ size_t* minimum_request_size, _Out_ size_t* minimum_reply_size)
{
    *minimum_request_size = 0;
    *minimum_reply_size = 0;

    if (operation_id > EBPF_OPERATION_GET_EC_FUNCTION || operation_id < EBPF_OPERATION_RESOLVE_HELPER)
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

    if (operation_id > EBPF_OPERATION_GET_EC_FUNCTION || operation_id < EBPF_OPERATION_RESOLVE_HELPER) {
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
