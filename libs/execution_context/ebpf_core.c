// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_maps.h"
#include "ebpf_pinning_table.h"
#include "ebpf_program.h"
#include "ebpf_serialize.h"
#include "ebpf_state.h"

const ebpf_handle_t ebpf_handle_invalid = (ebpf_handle_t)-1;

GUID ebpf_general_helper_function_interface_id = {/* 8d2a1d3f-9ce6-473d-b48e-17aa5c5581fe */
                                                  0x8d2a1d3f,
                                                  0x9ce6,
                                                  0x473d,
                                                  {0xb4, 0x8e, 0x17, 0xaa, 0x5c, 0x55, 0x81, 0xfe}};

static ebpf_pinning_table_t* _ebpf_core_map_pinning_table = NULL;

// Assume enabled until we can query it.
static ebpf_code_integrity_state_t _ebpf_core_code_integrity_state = EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE;

// Map related helpers.
static void*
_ebpf_core_map_find_element(ebpf_map_t* map, const uint8_t* key);
static int64_t
_ebpf_core_map_update_element(ebpf_map_t* map, const uint8_t* key, const uint8_t* data, uint64_t flags);
static int64_t
_ebpf_core_map_delete_element(ebpf_map_t* map, const uint8_t* key);

// Tail call.
static int64_t
_ebpf_core_tail_call(void* ctx, ebpf_map_t* map, uint32_t index);

// Utility functions.
static uint32_t
_ebpf_core_random_uint32();
static uint64_t
_ebpf_core_get_time_since_boot_ns();
static uint32_t
_ebpf_core_get_current_cpu();

#define EBPF_CORE_GLOBAL_HELPER_EXTENSION_VERSION 0

static ebpf_program_info_t _ebpf_global_helper_program_info = {{"global_helper", NULL, {0}}, 0, NULL};

static const void* _ebpf_general_helpers[] = {
    NULL,
    (void*)&_ebpf_core_map_find_element,
    (void*)&_ebpf_core_map_update_element,
    (void*)&_ebpf_core_map_delete_element,
    (void*)&_ebpf_core_tail_call,
    (void*)&_ebpf_core_random_uint32,
    (void*)&_ebpf_core_get_time_since_boot_ns,
    (void*)_ebpf_core_get_current_cpu};

static ebpf_extension_provider_t* _ebpf_global_helper_function_provider_context = NULL;
static ebpf_helper_function_addresses_t _ebpf_global_helper_function_dispatch_table = {
    EBPF_COUNT_OF(_ebpf_general_helpers), (uint64_t*)_ebpf_general_helpers};
static ebpf_program_data_t _ebpf_global_helper_function_program_data = {
    &_ebpf_global_helper_program_info, &_ebpf_global_helper_function_dispatch_table};

static ebpf_extension_data_t _ebpf_global_helper_function_extension_data = {
    EBPF_CORE_GLOBAL_HELPER_EXTENSION_VERSION,
    sizeof(_ebpf_global_helper_function_program_data),
    &_ebpf_global_helper_function_program_data};

ebpf_result_t
ebpf_core_initiate()
{
    ebpf_result_t return_value;

    return_value = ebpf_platform_initiate();
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = ebpf_epoch_initiate();
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = ebpf_state_initiate();
    if (return_value != EBPF_SUCCESS)
        goto Done;

    ebpf_object_tracking_initiate();

    return_value = ebpf_pinning_table_allocate(&_ebpf_core_map_pinning_table);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = ebpf_handle_table_initiate();
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = ebpf_program_initiate();
    if (return_value != EBPF_SUCCESS)
        goto Done;

    _ebpf_global_helper_program_info.count_of_helpers = ebpf_core_helper_functions_count;
    _ebpf_global_helper_program_info.helper_prototype = ebpf_core_helper_function_prototype;
    return_value = ebpf_provider_load(
        &_ebpf_global_helper_function_provider_context,
        &ebpf_general_helper_function_interface_id,
        NULL,
        &_ebpf_global_helper_function_extension_data,
        NULL,
        NULL,
        NULL,
        NULL);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_get_code_integrity_state(&_ebpf_core_code_integrity_state);

Done:
    if (return_value != EBPF_SUCCESS) {
        ebpf_core_terminate();
    }
    return return_value;
}

void
ebpf_core_terminate()
{
    ebpf_provider_unload(_ebpf_global_helper_function_provider_context);
    _ebpf_global_helper_function_provider_context = NULL;

    ebpf_program_terminate();

    ebpf_handle_table_terminate();

    ebpf_pinning_table_free(_ebpf_core_map_pinning_table);

    ebpf_state_terminate();

    // Shut down the epoch tracker and free any remaining memory or work items.
    // Note: Some objects may only be released on epoch termination.
    ebpf_epoch_flush();
    ebpf_epoch_terminate();

    // Verify that all ebpf_object_t objects have been freed.
    ebpf_object_tracking_terminate();

    ebpf_platform_terminate();
}

static ebpf_result_t
_ebpf_core_protocol_load_code(_In_ const ebpf_operation_load_code_request_t* request)
{
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;
    uint8_t* code = NULL;
    size_t code_length = 0;

    if (request->code_type == EBPF_CODE_NATIVE) {
        if (_ebpf_core_code_integrity_state == EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE) {
            retval = EBPF_BLOCKED_BY_POLICY;
            goto Done;
        }
    }

    retval = ebpf_reference_object_by_handle(request->program_handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
    if (retval != EBPF_SUCCESS)
        goto Done;

    code = (uint8_t*)request->code;
    code_length = request->header.length - EBPF_OFFSET_OF(ebpf_operation_load_code_request_t, code);

    retval = ebpf_program_load_code(program, request->code_type, code, code_length);
    if (retval != EBPF_SUCCESS)
        goto Done;

Done:
    ebpf_object_release_reference((ebpf_object_t*)program);
    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_resolve_helper(
    _In_ const struct _ebpf_operation_resolve_helper_request* request,
    _Inout_ struct _ebpf_operation_resolve_helper_reply* reply,
    uint16_t reply_length)
{
    ebpf_program_t* program = NULL;
    ebpf_result_t return_value = EBPF_SUCCESS;
    size_t count_of_helpers =
        (request->header.length - EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id)) /
        sizeof(request->helper_id[0]);
    size_t required_reply_length =
        EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + count_of_helpers * sizeof(reply->address[0]);
    size_t helper_index;
    uint32_t* request_helper_ids = NULL;

    if (reply_length < required_reply_length) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (count_of_helpers == 0)
        goto Done;

    request_helper_ids = (uint32_t*)ebpf_allocate(count_of_helpers * sizeof(uint32_t));
    if (request_helper_ids == NULL) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }
    for (helper_index = 0; helper_index < count_of_helpers; helper_index++)
        request_helper_ids[helper_index] = request->helper_id[helper_index];

    return_value =
        ebpf_reference_object_by_handle(request->program_handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = ebpf_program_set_helper_function_ids(program, count_of_helpers, request_helper_ids);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = ebpf_program_get_helper_function_addresses(program, count_of_helpers, reply->address);
    if (return_value != EBPF_SUCCESS)
        goto Done;

Done:
    if (return_value == EBPF_SUCCESS)
        reply->header.length = (uint16_t)required_reply_length;

    ebpf_object_release_reference((ebpf_object_t*)program);
    ebpf_free(request_helper_ids);
    return return_value;
}

static ebpf_result_t
_ebpf_core_protocol_resolve_map(
    _In_ const struct _ebpf_operation_resolve_map_request* request,
    _Inout_ struct _ebpf_operation_resolve_map_reply* reply,
    uint16_t reply_length)
{
    ebpf_program_t* program = NULL;
    size_t count_of_maps = (request->header.length - EBPF_OFFSET_OF(ebpf_operation_resolve_map_request_t, map_handle)) /
                           sizeof(request->map_handle[0]);
    size_t required_reply_length =
        EBPF_OFFSET_OF(ebpf_operation_resolve_map_reply_t, address) + count_of_maps * sizeof(reply->address[0]);
    size_t map_index;
    ebpf_result_t return_value;

    if (reply_length < required_reply_length) {
        return EBPF_INVALID_ARGUMENT;
    }

    return_value =
        ebpf_reference_object_by_handle(request->program_handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    for (map_index = 0; map_index < count_of_maps; map_index++) {
        ebpf_map_t* map;
        return_value =
            ebpf_reference_object_by_handle(request->map_handle[map_index], EBPF_OBJECT_MAP, (ebpf_object_t**)&map);

        if (return_value != EBPF_SUCCESS)
            goto Done;

        reply->address[map_index] = (uint64_t)map;

        ebpf_object_release_reference((ebpf_object_t*)map);
    }

    return_value = ebpf_program_associate_maps(program, (ebpf_map_t**)reply->address, count_of_maps);

    reply->header.length = (uint16_t)required_reply_length;

Done:
    ebpf_object_release_reference((ebpf_object_t*)program);

    return return_value;
}

static ebpf_result_t
_ebpf_core_protocol_create_map(
    _In_ const struct _ebpf_operation_create_map_request* request,
    _Inout_ struct _ebpf_operation_create_map_reply* reply,
    uint16_t reply_length)
{
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    UNREFERENCED_PARAMETER(reply_length);
    ebpf_utf8_string_t map_name = {0};

    if (request->header.length > sizeof(ebpf_operation_create_map_request_t)) {
        map_name.value = (uint8_t*)request->data;
        map_name.length = ((uint8_t*)request) + request->header.length - ((uint8_t*)request->data);
    }

    retval = ebpf_map_create(&map_name, &request->ebpf_map_definition, request->inner_map_handle, &map);
    if (retval != EBPF_SUCCESS)
        return retval;

    ebpf_object_t* map_object = (ebpf_object_t*)map;

    retval = ebpf_handle_create(&reply->handle, map_object);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = EBPF_SUCCESS;

Done:
    ebpf_object_release_reference(map_object);

    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_create_program(
    _In_ const ebpf_operation_create_program_request_t* request,
    _Inout_ ebpf_operation_create_program_reply_t* reply,
    uint16_t reply_length)
{
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;
    ebpf_program_parameters_t parameters;
    uint8_t* file_name = NULL;
    size_t file_name_length = 0;
    uint8_t* section_name = NULL;
    size_t section_name_length = 0;
    uint8_t* program_name = NULL;
    size_t program_name_length = 0;

    UNREFERENCED_PARAMETER(reply_length);

    if (request->program_name_offset > request->header.length) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }
    file_name = (uint8_t*)request->data;
    section_name = ((uint8_t*)request) + request->section_name_offset;
    program_name = ((uint8_t*)request) + request->program_name_offset;
    file_name_length = section_name - file_name;
    section_name_length = program_name - section_name;
    program_name_length = ((uint8_t*)request) + request->header.length - program_name;

    retval = ebpf_program_create(&program);
    if (retval != EBPF_SUCCESS)
        goto Done;

    parameters.program_type = request->program_type;
    parameters.program_name.value = program_name;
    parameters.program_name.length = program_name_length;
    parameters.section_name.value = section_name;
    parameters.section_name.length = section_name_length;
    parameters.file_name.value = file_name;
    parameters.file_name.length = file_name_length;

    retval = ebpf_program_initialize(program, &parameters);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_handle_create(&reply->program_handle, (ebpf_object_t*)program);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = EBPF_SUCCESS;

Done:
    ebpf_object_release_reference((ebpf_object_t*)program);

    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_map_find_element(
    _In_ const ebpf_operation_map_find_element_request_t* request,
    _Inout_ ebpf_operation_map_find_element_reply_t* reply,
    uint16_t reply_length)
{
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    size_t value_length;
    size_t key_length;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(ebpf_operation_map_find_element_request_t, key), &key_length);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_safe_size_t_subtract(
        reply_length, EBPF_OFFSET_OF(ebpf_operation_map_find_element_reply_t, value), &value_length);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_map_find_entry(map, key_length, request->key, value_length, reply->value, 0);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = EBPF_SUCCESS;
    reply->header.length = reply_length;

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);
    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_map_update_element(_In_ const epf_operation_map_update_element_request_t* request)
{
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    size_t value_length;
    size_t key_length;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
    if (retval != EBPF_SUCCESS)
        goto Done;

    const ebpf_map_definition_in_memory_t* map_definition = ebpf_map_get_definition(map);

    retval = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(epf_operation_map_update_element_request_t, data), &value_length);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_safe_size_t_subtract(value_length, map_definition->key_size, &value_length);
    if (retval != EBPF_SUCCESS)
        goto Done;

    key_length = map_definition->key_size;

    retval = ebpf_map_update_entry(
        map, key_length, request->data, value_length, request->data + key_length, request->option, 0);

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);
    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_map_update_element_with_handle(
    _In_ const ebpf_operation_map_update_element_with_handle_request_t* request)
{
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    size_t key_length;

    retval = ebpf_reference_object_by_handle(request->map_handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
    if (retval != EBPF_SUCCESS)
        goto Done;

    const ebpf_map_definition_in_memory_t* map_definition = ebpf_map_get_definition(map);

    retval = ebpf_safe_size_t_subtract(
        request->header.length,
        EBPF_OFFSET_OF(ebpf_operation_map_update_element_with_handle_request_t, key),
        &key_length);
    if (retval != EBPF_SUCCESS)
        goto Done;

    if (key_length != map_definition->key_size) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    retval = ebpf_map_update_entry_with_handle(map, key_length, request->key, request->value_handle, request->option);

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);
    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_map_delete_element(_In_ const ebpf_operation_map_delete_element_request_t* request)
{
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    size_t key_length;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(ebpf_operation_map_delete_element_request_t, key), &key_length);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_map_delete_entry(map, key_length, request->key, 0);

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);
    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_map_get_next_key(
    _In_ const ebpf_operation_map_get_next_key_request_t* request,
    _Inout_ ebpf_operation_map_get_next_key_reply_t* reply,
    uint16_t reply_length)
{
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    size_t previous_key_length;
    size_t next_key_length;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_object_t**)&map);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_safe_size_t_subtract(
        request->header.length,
        EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key),
        &previous_key_length);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_safe_size_t_subtract(
        reply_length, EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_reply_t, next_key), &next_key_length);
    if (retval != EBPF_SUCCESS)
        goto Done;

    if (previous_key_length != 0 && previous_key_length != next_key_length) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    retval = ebpf_map_next_key(
        map, next_key_length, previous_key_length == 0 ? NULL : request->previous_key, reply->next_key);

Done:
    ebpf_object_release_reference((ebpf_object_t*)map);

    return retval;
}

static ebpf_result_t
_ebpf_core_get_next_handle(ebpf_handle_t previous_handle, ebpf_object_type_t type, ebpf_handle_t* next_handle)
{
    ebpf_result_t retval;
    ebpf_object_t* previous_object = NULL;
    ebpf_object_t* next_object = NULL;

    if (previous_handle != UINT64_MAX) {
        retval = ebpf_reference_object_by_handle(previous_handle, type, (ebpf_object_t**)&previous_object);
        if (retval != EBPF_SUCCESS)
            goto Done;
    }

    ebpf_object_reference_next_object(previous_object, type, &next_object);

    if (next_object)
        retval = ebpf_handle_create(next_handle, next_object);
    else
        *next_handle = UINT64_MAX;

    retval = EBPF_SUCCESS;

Done:
    ebpf_object_release_reference(previous_object);
    ebpf_object_release_reference(next_object);

    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_get_next_map(
    _In_ const struct _ebpf_operation_get_next_map_request* request,
    _Inout_ struct _ebpf_operation_get_next_map_reply* reply,
    uint16_t reply_length)
{
    UNREFERENCED_PARAMETER(reply_length);
    return _ebpf_core_get_next_handle(request->previous_handle, EBPF_OBJECT_MAP, &reply->next_handle);
}

static ebpf_result_t
_ebpf_core_protocol_get_next_program(
    _In_ const struct _ebpf_operation_get_next_program_request* request,
    _Inout_ struct _ebpf_operation_get_next_program_reply* reply,
    uint16_t reply_length)
{
    UNREFERENCED_PARAMETER(reply_length);
    return _ebpf_core_get_next_handle(request->previous_handle, EBPF_OBJECT_PROGRAM, &reply->next_handle);
}

static ebpf_result_t
_ebpf_core_protocol_query_map_definition(
    _In_ const struct _ebpf_operation_query_map_definition_request* request,
    _Inout_ struct _ebpf_operation_query_map_definition_reply* reply,
    uint16_t reply_length)
{
    UNREFERENCED_PARAMETER(reply_length);

    ebpf_object_t* object;
    ebpf_result_t result = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_MAP, &object);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    ebpf_map_t* map = (ebpf_map_t*)object;
    reply->map_definition = *ebpf_map_get_definition(map);
    reply->map_definition.value_size = ebpf_map_get_effective_value_size(map);

    ebpf_object_release_reference(object);

    return EBPF_SUCCESS;
}

static ebpf_result_t
_ebpf_core_protocol_query_program_info(
    _In_ const struct _ebpf_operation_query_program_info_request* request,
    _Inout_ struct _ebpf_operation_query_program_info_reply* reply,
    uint16_t reply_length)
{
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;
    size_t required_reply_length;
    const ebpf_program_parameters_t* parameters;

    retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
    if (retval != EBPF_SUCCESS)
        goto Done;

    parameters = ebpf_program_get_parameters(program);

    retval =
        ebpf_safe_size_t_add(parameters->section_name.length, parameters->file_name.length, &required_reply_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }
    retval = ebpf_safe_size_t_add(
        EBPF_OFFSET_OF(struct _ebpf_operation_query_program_info_reply, data),
        required_reply_length,
        &required_reply_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    if (reply_length < required_reply_length) {
        return EBPF_INVALID_ARGUMENT;
    }

    reply->file_name_offset = EBPF_OFFSET_OF(struct _ebpf_operation_query_program_info_reply, data);
    reply->section_name_offset = reply->file_name_offset + (uint16_t)parameters->file_name.length;

    memcpy(reply->data, parameters->file_name.value, parameters->file_name.length);
    memcpy(reply->data + parameters->file_name.length, parameters->section_name.value, parameters->section_name.length);
    reply->code_type = parameters->code_type;

    reply->header.length = (uint16_t)required_reply_length;

Done:
    ebpf_object_release_reference((ebpf_object_t*)program);

    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_update_pinning(_In_ const struct _ebpf_operation_update_map_pinning_request* request)
{
    ebpf_result_t retval;
    const ebpf_utf8_string_t name = {
        (uint8_t*)request->name,
        request->header.length - EBPF_OFFSET_OF(ebpf_operation_update_pinning_request_t, name)};
    ebpf_object_t* object = NULL;

    if (name.length == 0) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (request->handle == UINT64_MAX) {
        retval = ebpf_pinning_table_delete(_ebpf_core_map_pinning_table, &name);
        goto Done;
    } else {
        retval = ebpf_reference_object_by_handle(request->handle, EBPF_OBJECT_UNKNOWN, (ebpf_object_t**)&object);
        if (retval != EBPF_SUCCESS)
            goto Done;

        retval = ebpf_pinning_table_insert(_ebpf_core_map_pinning_table, &name, (ebpf_object_t*)object);
    }
Done:
    ebpf_object_release_reference((ebpf_object_t*)object);

    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_get_pinned_object(
    _In_ const struct _ebpf_operation_get_pinning_request* request,
    _Inout_ struct _ebpf_operation_get_pinning_reply* reply,
    uint16_t reply_length)
{
    ebpf_result_t retval;
    ebpf_object_t* object = NULL;
    const ebpf_utf8_string_t name = {
        (uint8_t*)request->name, request->header.length - EBPF_OFFSET_OF(ebpf_operation_get_pinning_request_t, name)};
    UNREFERENCED_PARAMETER(reply_length);

    if (name.length == 0) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    retval = ebpf_pinning_table_find(_ebpf_core_map_pinning_table, &name, (ebpf_object_t**)&object);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_handle_create(&reply->handle, (ebpf_object_t*)object);

Done:
    ebpf_object_release_reference((ebpf_object_t*)object);
    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_link_program(
    _In_ const ebpf_operation_link_program_request_t* request, _Inout_ ebpf_operation_link_program_reply_t* reply)
{
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;
    ebpf_link_t* link = NULL;

    retval = ebpf_reference_object_by_handle(request->program_handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_link_create(&link);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_link_initialize(link, request->attach_type, NULL, 0);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_link_attach_program(link, program);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_handle_create(&reply->link_handle, (ebpf_object_t*)link);
    if (retval != EBPF_SUCCESS)
        goto Done;

Done:
    if (retval != EBPF_SUCCESS) {
        ebpf_link_detach_program(link);
    }
    ebpf_object_release_reference((ebpf_object_t*)program);
    ebpf_object_release_reference((ebpf_object_t*)link);
    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_unlink_program(_In_ const ebpf_operation_unlink_program_request_t* request)
{
    ebpf_result_t retval;
    ebpf_link_t* link = NULL;

    retval = ebpf_reference_object_by_handle(request->link_handle, EBPF_OBJECT_LINK, (ebpf_object_t**)&link);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    ebpf_link_detach_program(link);

Done:
    ebpf_object_release_reference((ebpf_object_t*)link);
    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_close_handle(_In_ const ebpf_operation_close_handle_request_t* request)
{
    return ebpf_handle_close(request->handle);
}

static uint64_t
_ebpf_core_protocol_get_ec_function(
    _In_ const ebpf_operation_get_ec_function_request_t* request, _Inout_ ebpf_operation_get_ec_function_reply_t* reply)
{
    if (request->function != EBPF_EC_FUNCTION_LOG)
        return EBPF_INVALID_ARGUMENT;

    reply->address = (uint64_t)ebpf_log_function;
    return EBPF_SUCCESS;
}

static ebpf_result_t
_ebpf_core_protocol_get_program_info(
    _In_ const ebpf_operation_get_program_info_request_t* request,
    _Inout_ ebpf_operation_get_program_info_reply_t* reply,
    uint16_t reply_length)
{
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;
    ebpf_program_parameters_t program_parameters = {0};
    ebpf_program_info_t* program_info = NULL;
    size_t serialization_buffer_size;
    size_t required_length;

    program_parameters.program_type = request->program_type;

    if (request->program_handle == ebpf_handle_invalid) {
        retval = ebpf_program_create(&program);
        if (retval != EBPF_SUCCESS)
            goto Done;
        retval = ebpf_program_initialize(program, &program_parameters);
        if (retval != EBPF_SUCCESS)
            goto Done;
    } else {
        retval =
            ebpf_reference_object_by_handle(request->program_handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
        if (retval != EBPF_SUCCESS)
            goto Done;
    }

    retval = ebpf_program_get_program_info(program, &program_info);
    if (retval != EBPF_SUCCESS)
        goto Done;
    if (program_info == NULL) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    serialization_buffer_size = reply_length - EBPF_OFFSET_OF(ebpf_operation_get_program_info_reply_t, data);

    // Serialize program info structure onto reply data buffer.
    retval = ebpf_serialize_program_info(
        program_info, reply->data, serialization_buffer_size, &reply->size, &required_length);

    if (retval != EBPF_SUCCESS) {
        reply->header.length =
            (uint16_t)(required_length + EBPF_OFFSET_OF(ebpf_operation_get_program_info_reply_t, data));
        goto Done;
    }

Done:
    ebpf_program_free_program_info(program_info);
    ebpf_object_release_reference((ebpf_object_t*)program);
    return retval;
}

static ebpf_result_t
_ebpf_core_protocol_convert_pinning_entries_to_map_info_array(
    uint16_t entry_count,
    _In_reads_opt_(entry_count) ebpf_pinning_entry_t* pinning_entries,
    _Outptr_result_buffer_maybenull_(entry_count) ebpf_map_info_internal_t** map_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_map_info_internal_t* local_map_info = NULL;
    uint16_t index;

    if (map_info == NULL) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if ((entry_count == 0) || (pinning_entries == NULL))
        goto Exit;

    local_map_info = (ebpf_map_info_internal_t*)ebpf_allocate(sizeof(ebpf_map_info_internal_t) * entry_count);
    if (local_map_info == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    for (index = 0; index < entry_count; index++) {
        ebpf_pinning_entry_t* source = &pinning_entries[index];
        ebpf_map_info_internal_t* destination = &local_map_info[index];

        if (ebpf_object_get_type(source->object) != EBPF_OBJECT_MAP) {
            // Bad object type.
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        // Query map defintion.
        const ebpf_map_definition_in_memory_t* map_definition = ebpf_map_get_definition((ebpf_map_t*)source->object);
        destination->definition = *map_definition;
        destination->definition.value_size = ebpf_map_get_effective_value_size((ebpf_map_t*)source->object);
        // Set pin path. No need to duplicate.
        destination->pin_path = source->name;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        ebpf_free(local_map_info);
        local_map_info = NULL;
    }

    *map_info = local_map_info;
    return result;
}

static ebpf_result_t
_ebpf_core_protocol_serialize_map_info_reply(
    uint16_t map_count,
    _In_count_(map_count) const ebpf_map_info_internal_t* map_info,
    size_t output_buffer_length,
    _In_ ebpf_operation_get_map_info_reply_t* map_info_reply)
{
    ebpf_result_t result = EBPF_SUCCESS;
    size_t serialization_buffer_size;
    size_t required_serialization_length;

    serialization_buffer_size = output_buffer_length - EBPF_OFFSET_OF(ebpf_operation_get_map_info_reply_t, data);

    result = ebpf_serialize_internal_map_info_array(
        map_count,
        map_info,
        map_info_reply->data,
        (const size_t)serialization_buffer_size,
        &map_info_reply->size,
        &required_serialization_length);

    if (result != EBPF_SUCCESS) {
        map_info_reply->header.length =
            (uint16_t)(required_serialization_length + EBPF_OFFSET_OF(ebpf_operation_get_map_info_reply_t, data));
    } else
        map_info_reply->map_count = map_count;

    return result;
}

static ebpf_result_t
_ebpf_core_protocol_get_map_info(
    _In_ const ebpf_operation_get_map_info_request_t* request,
    _In_ ebpf_operation_get_map_info_reply_t* reply,
    uint16_t reply_length)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint16_t entry_count = 0;
    ebpf_pinning_entry_t* pinning_entries = NULL;
    ebpf_map_info_internal_t* map_info = NULL;

    UNREFERENCED_PARAMETER(request);

    // Enumerate all the pinning entries for map objects.
    result = ebpf_pinning_table_enumerate_entries(
        _ebpf_core_map_pinning_table, EBPF_OBJECT_MAP, &entry_count, &pinning_entries);
    if (result != EBPF_SUCCESS)
        goto Exit;

    if (entry_count == 0)
        // No pinned map entries to return.
        goto Exit;

    // Convert pinning entries to map_info_t array.
    result = _ebpf_core_protocol_convert_pinning_entries_to_map_info_array(entry_count, pinning_entries, &map_info);
    if (result != EBPF_SUCCESS)
        goto Exit;

    _Analysis_assume_(map_info != NULL);

    // Serialize map info array onto reply structure.
    _Analysis_assume_(map_info != NULL);
    result = _ebpf_core_protocol_serialize_map_info_reply(entry_count, map_info, reply_length, reply);

Exit:

    ebpf_free(map_info);
    ebpf_pinning_entries_release(entry_count, pinning_entries);

    return result;
}

static ebpf_result_t
_get_handle_by_id(
    ebpf_object_type_t type,
    _In_ const ebpf_operation_get_handle_by_id_request_t* request,
    _Out_ ebpf_operation_get_handle_by_id_reply_t* reply,
    uint16_t reply_length)
{
    if (reply_length < sizeof(*reply)) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_object_t* object;
    ebpf_result_t result = ebpf_object_reference_by_id(request->id, type, &object);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    reply->header.length = sizeof(reply->header);

    result = ebpf_handle_create(&reply->handle, object);
    ebpf_object_release_reference(object);

    return result;
}

static ebpf_result_t
_ebpf_core_protocol_get_map_handle_by_id(
    _In_ const ebpf_operation_get_handle_by_id_request_t* request,
    _Out_ ebpf_operation_get_handle_by_id_reply_t* reply,
    uint16_t reply_length)
{
    return _get_handle_by_id(EBPF_OBJECT_MAP, request, reply, reply_length);
}

static ebpf_result_t
_ebpf_core_protocol_get_program_handle_by_id(
    _In_ const ebpf_operation_get_handle_by_id_request_t* request,
    _Out_ ebpf_operation_get_handle_by_id_reply_t* reply,
    uint16_t reply_length)
{
    return _get_handle_by_id(EBPF_OBJECT_PROGRAM, request, reply, reply_length);
}

static ebpf_result_t
_ebpf_core_protocol_get_link_handle_by_id(
    _In_ const ebpf_operation_get_handle_by_id_request_t* request,
    _Out_ ebpf_operation_get_handle_by_id_reply_t* reply,
    uint16_t reply_length)
{
    return _get_handle_by_id(EBPF_OBJECT_LINK, request, reply, reply_length);
}

static ebpf_result_t
_get_next_id(
    ebpf_object_type_t type,
    _In_ const ebpf_operation_get_next_id_request_t* request,
    _Out_ ebpf_operation_get_next_id_reply_t* reply,
    uint16_t reply_length)
{
    if (reply_length < sizeof(*reply)) {
        return EBPF_INVALID_ARGUMENT;
    }

    return ebpf_object_get_next_id(request->start_id, type, &reply->next_id);
}

static ebpf_result_t
_ebpf_core_protocol_get_next_link_id(
    _In_ const ebpf_operation_get_next_id_request_t* request,
    _Out_ ebpf_operation_get_next_id_reply_t* reply,
    uint16_t reply_length)
{
    return _get_next_id(EBPF_OBJECT_LINK, request, reply, reply_length);
}

static ebpf_result_t
_ebpf_core_protocol_get_next_map_id(
    _In_ const ebpf_operation_get_next_id_request_t* request,
    _Out_ ebpf_operation_get_next_id_reply_t* reply,
    uint16_t reply_length)
{
    return _get_next_id(EBPF_OBJECT_MAP, request, reply, reply_length);
}

static ebpf_result_t
_ebpf_core_protocol_get_next_program_id(
    _In_ const ebpf_operation_get_next_id_request_t* request,
    _Out_ ebpf_operation_get_next_id_reply_t* reply,
    uint16_t reply_length)
{
    return _get_next_id(EBPF_OBJECT_PROGRAM, request, reply, reply_length);
}

static void*
_ebpf_core_map_find_element(ebpf_map_t* map, const uint8_t* key)
{
    ebpf_result_t retval;
    uint8_t* value;
    retval = ebpf_map_find_entry(map, 0, key, sizeof(&value), (uint8_t*)&value, EBPF_MAP_FLAG_HELPER);
    if (retval != EBPF_SUCCESS)
        return NULL;
    else
        return value;
}

static int64_t
_ebpf_core_map_update_element(ebpf_map_t* map, const uint8_t* key, const uint8_t* value, uint64_t flags)
{
    return -ebpf_map_update_entry(map, 0, key, 0, value, flags, EBPF_MAP_FLAG_HELPER);
}

static int64_t
_ebpf_core_map_delete_element(ebpf_map_t* map, const uint8_t* key)
{
    return -ebpf_map_delete_entry(map, 0, key, EBPF_MAP_FLAG_HELPER);
}

static int64_t
_ebpf_core_tail_call(void* context, ebpf_map_t* map, uint32_t index)
{
    UNREFERENCED_PARAMETER(context);

    // Get program from map[index].
    ebpf_program_t* callee = ebpf_map_get_program_from_entry(map, sizeof(index), (uint8_t*)&index);
    if (callee == NULL) {
        return -EBPF_INVALID_ARGUMENT;
    }
    return -ebpf_program_set_tail_call(callee);
}

static uint32_t
_ebpf_core_random_uint32()
{
    return ebpf_random_uint32();
}

static uint64_t
_ebpf_core_get_time_since_boot_ns()
{
    // ebpf_query_interrupt_time_precise returns time elapsed since
    // boot in units of 100 ns.
    return ebpf_query_interrupt_time_precise() * 100;
}

static uint32_t
_ebpf_core_get_current_cpu()
{
    return ebpf_get_current_cpu();
}

typedef struct _ebpf_protocol_handler
{
    union
    {
        ebpf_result_t (*protocol_handler_no_reply)(_In_ const void* input_buffer);
        ebpf_result_t (*protocol_handler_with_reply)(
            _In_ const void* input_buffer,
            _Out_writes_bytes_(output_buffer_length) void* output_buffer,
            uint16_t output_buffer_length);
    } dispatch;
    size_t minimum_request_size;
    size_t minimum_reply_size;
} const ebpf_protocol_handler_t;

static ebpf_protocol_handler_t _ebpf_protocol_handlers[] = {
    // EBPF_OPERATION_RESOLVE_HELPER
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_resolve_helper,
     EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id),
     sizeof(struct _ebpf_operation_resolve_helper_reply)},

    // EBPF_OPERATION_RESOLVE_MAP
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_resolve_map,
     EBPF_OFFSET_OF(ebpf_operation_resolve_map_request_t, map_handle),
     sizeof(struct _ebpf_operation_resolve_map_reply)},

    // EBPF_OPERATION_CREATE_PROGRAM
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_create_program,
     EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data),
     sizeof(struct _ebpf_operation_create_program_reply)},

    // EBPF_OPERATION_CREATE_MAP
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_create_map,
     EBPF_OFFSET_OF(ebpf_operation_create_map_request_t, data),
     sizeof(struct _ebpf_operation_create_map_reply)},

    // EBPF_OPERATION_LOAD_CODE
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_load_code,
     EBPF_OFFSET_OF(ebpf_operation_load_code_request_t, code),
     0},

    // EBPF_OPERATION_MAP_FIND_ELEMENT
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_map_find_element,
     EBPF_OFFSET_OF(ebpf_operation_map_find_element_request_t, key),
     EBPF_OFFSET_OF(ebpf_operation_map_find_element_reply_t, value)},

    // EBPF_OPERATION_MAP_UPDATE_ELEMENT
    {_ebpf_core_protocol_map_update_element, EBPF_OFFSET_OF(epf_operation_map_update_element_request_t, data), 0},

    // EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE
    {_ebpf_core_protocol_map_update_element_with_handle,
     EBPF_OFFSET_OF(ebpf_operation_map_update_element_with_handle_request_t, key),
     0},

    // EBPF_OPERATION_MAP_DELETE_ELEMENT
    {_ebpf_core_protocol_map_delete_element, EBPF_OFFSET_OF(ebpf_operation_map_delete_element_request_t, key), 0},

    // EBPF_OPERATION_MAP_GET_NEXT_KEY
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_map_get_next_key,
     EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key),
     EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_reply_t, next_key)},

    // EBPF_OPERATION_GET_NEXT_MAP
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_next_map,
     sizeof(struct _ebpf_operation_get_next_map_request),
     sizeof(struct _ebpf_operation_get_next_map_reply)},

    // EBPF_OPERATION_GET_NEXT_PROGRAM
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_next_program,
     sizeof(struct _ebpf_operation_get_next_program_request),
     sizeof(struct _ebpf_operation_get_next_program_reply)},

    // EBPF_OPERATION_QUERY_MAP_DEFINITION
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_query_map_definition,
     sizeof(struct _ebpf_operation_query_map_definition_request),
     sizeof(struct _ebpf_operation_query_map_definition_reply)},

    // EBPF_OPERATION_QUERY_PROGRAM_INFO
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_query_program_info,
     sizeof(struct _ebpf_operation_query_program_info_request),
     EBPF_OFFSET_OF(ebpf_operation_query_program_info_reply_t, data)},

    // EBPF_OPERATION_UPDATE_PINNING
    {_ebpf_core_protocol_update_pinning, EBPF_OFFSET_OF(ebpf_operation_update_pinning_request_t, name), 0},

    // EBPF_OPERATION_GET_PINNING
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_pinned_object,
     EBPF_OFFSET_OF(ebpf_operation_get_pinning_request_t, name),
     sizeof(struct _ebpf_operation_get_pinning_reply)},

    // EBPF_OPERATION_LINK_PROGRAM
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_link_program,
     EBPF_OFFSET_OF(ebpf_operation_link_program_request_t, data),
     sizeof(ebpf_operation_link_program_reply_t)},

    // EBPF_OPERATION_UNLINK_PROGRAM
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_unlink_program,
     sizeof(ebpf_operation_unlink_program_request_t),
     0},

    // EBPF_OPERATION_CLOSE_HANDLE
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_close_handle,
     sizeof(ebpf_operation_close_handle_request_t),
     0},

    // EBPF_OPERATION_GET_EC_FUNCTION
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_ec_function,
     sizeof(ebpf_operation_get_ec_function_request_t),
     sizeof(ebpf_operation_get_ec_function_reply_t)},

    // EBPF_OPERATION_GET_PROGRAM_INFO
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_program_info,
     sizeof(ebpf_operation_get_program_info_request_t),
     EBPF_OFFSET_OF(ebpf_operation_get_program_info_reply_t, data)},

    // EBPF_OPERATION_GET_MAP_INFO
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_map_info,
     sizeof(ebpf_operation_get_map_info_request_t),
     EBPF_OFFSET_OF(ebpf_operation_get_map_info_reply_t, data)},

    // EBPF_OPERATION_GET_LINK_HANDLE_BY_ID
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_link_handle_by_id,
     sizeof(ebpf_operation_get_handle_by_id_request_t),
     sizeof(ebpf_operation_get_handle_by_id_reply_t)},

    // EBPF_OPERATION_GET_MAP_HANDLE_BY_ID
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_map_handle_by_id,
     sizeof(ebpf_operation_get_handle_by_id_request_t),
     sizeof(ebpf_operation_get_handle_by_id_reply_t)},

    // EBPF_OPERATION_GET_PROGRAM_HANDLE_BY_ID
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_program_handle_by_id,
     sizeof(ebpf_operation_get_handle_by_id_request_t),
     sizeof(ebpf_operation_get_handle_by_id_reply_t)},

    // EBPF_OPERATION_GET_NEXT_LINK_ID
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_next_link_id,
     sizeof(ebpf_operation_get_next_id_request_t),
     sizeof(ebpf_operation_get_next_id_reply_t)},

    // EBPF_OPERATION_GET_NEXT_MAP_ID
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_next_map_id,
     sizeof(ebpf_operation_get_next_id_request_t),
     sizeof(ebpf_operation_get_next_id_reply_t)},

    // EBPF_OPERATION_GET_NEXT_PROGRAM_ID
    {(ebpf_result_t(__cdecl*)(const void*))_ebpf_core_protocol_get_next_program_id,
     sizeof(ebpf_operation_get_next_id_request_t),
     sizeof(ebpf_operation_get_next_id_reply_t)},
};

ebpf_result_t
ebpf_core_get_protocol_handler_properties(
    ebpf_operation_id_t operation_id, _Out_ size_t* minimum_request_size, _Out_ size_t* minimum_reply_size)
{
    *minimum_request_size = 0;
    *minimum_reply_size = 0;

    if (operation_id >= EBPF_COUNT_OF(_ebpf_protocol_handlers) || operation_id < EBPF_OPERATION_RESOLVE_HELPER)
        return EBPF_OPERATION_NOT_SUPPORTED;

    if (!_ebpf_protocol_handlers[operation_id].dispatch.protocol_handler_no_reply)
        return EBPF_OPERATION_NOT_SUPPORTED;

    *minimum_request_size = _ebpf_protocol_handlers[operation_id].minimum_request_size;
    *minimum_reply_size = _ebpf_protocol_handlers[operation_id].minimum_reply_size;
    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_core_invoke_protocol_handler(
    ebpf_operation_id_t operation_id,
    _In_ const void* input_buffer,
    _Out_writes_bytes_opt_(output_buffer_length) void* output_buffer,
    uint16_t output_buffer_length)
{
    ebpf_result_t retval;

    if (operation_id >= EBPF_COUNT_OF(_ebpf_protocol_handlers) || operation_id < EBPF_OPERATION_RESOLVE_HELPER) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    retval = ebpf_epoch_enter();
    if (retval != EBPF_SUCCESS)
        return retval;

    if (output_buffer == NULL)
        retval = _ebpf_protocol_handlers[operation_id].dispatch.protocol_handler_no_reply(input_buffer);
    else
        retval = _ebpf_protocol_handlers[operation_id].dispatch.protocol_handler_with_reply(
            input_buffer, output_buffer, output_buffer_length);

    ebpf_epoch_exit();
    return retval;
}
