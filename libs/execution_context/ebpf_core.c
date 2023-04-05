// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_async.h"
#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_maps.h"
#include "ebpf_native.h"
#include "ebpf_pinning_table.h"
#include "ebpf_program.h"
#include "ebpf_serialize.h"
#include "ebpf_state.h"

#include <errno.h>

GUID ebpf_program_information_extension_interface_id;
GUID ebpf_hook_extension_interface_id;

GUID ebpf_general_helper_function_module_id = {/* 8d2a1d3f-9ce6-473d-b48e-17aa5c5581fe */
                                               0x8d2a1d3f,
                                               0x9ce6,
                                               0x473d,
                                               {0xb4, 0x8e, 0x17, 0xaa, 0x5c, 0x55, 0x81, 0xfe}};

static ebpf_pinning_table_t* _ebpf_core_map_pinning_table = NULL;

// Assume enabled until we can query it.
static ebpf_code_integrity_state_t _ebpf_core_code_integrity_state = EBPF_CODE_INTEGRITY_HYPERVISOR_KERNEL_MODE;

static void*
_ebpf_core_map_find_element(ebpf_map_t* map, const uint8_t* key);
static int64_t
_ebpf_core_map_update_element(ebpf_map_t* map, const uint8_t* key, const uint8_t* data, uint64_t flags);
static int64_t
_ebpf_core_map_delete_element(ebpf_map_t* map, const uint8_t* key);
static void*
_ebpf_core_map_find_and_delete_element(_Inout_ ebpf_map_t* map, _In_ const uint8_t* key);
static int64_t
_ebpf_core_tail_call(void* ctx, ebpf_map_t* map, uint32_t index);
static uint64_t
_ebpf_core_get_time_since_boot_ns();
static uint64_t
_ebpf_core_get_time_ns();
static long
_ebpf_core_trace_printk2(_In_reads_(fmt_size) const char* fmt, size_t fmt_size);
static long
_ebpf_core_trace_printk3(_In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3);
static long
_ebpf_core_trace_printk4(_In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3, uint64_t arg4);
static long
_ebpf_core_trace_printk5(
    _In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3, uint64_t arg4, uint64_t arg5);
static int
_ebpf_core_ring_buffer_output(
    _Inout_ ebpf_map_t* map, _In_reads_bytes_(length) uint8_t* data, size_t length, uint64_t flags);
static uint64_t
_ebpf_core_map_push_elem(_Inout_ ebpf_map_t* map, _In_ const uint8_t* value, uint64_t flags);
static uint64_t
_ebpf_core_map_pop_elem(_Inout_ ebpf_map_t* map, _Out_ uint8_t* value);
static uint64_t
_ebpf_core_map_peek_elem(_Inout_ ebpf_map_t* map, _Out_ uint8_t* value);
static uint64_t
_ebpf_core_get_pid_tgid();
static uint64_t
_ebpf_core_get_current_logon_id(_In_ const void* ctx);
static int32_t
_ebpf_core_is_current_admin(_In_ const void* ctx);

#define EBPF_CORE_GLOBAL_HELPER_EXTENSION_VERSION 0

static ebpf_program_info_t _ebpf_global_helper_program_info = {{"global_helper", NULL, {0}}, 0, NULL};

// Order of elements in this table must match the order of the elements in ebpf_core_helper_function_prototype.
static const void* _ebpf_general_helpers[] = {
    // Map related helpers.
    (void*)&_ebpf_core_map_find_element,
    (void*)&_ebpf_core_map_update_element,
    (void*)&_ebpf_core_map_delete_element,
    (void*)&_ebpf_core_map_find_and_delete_element,
    // Tail call.
    (void*)&_ebpf_core_tail_call,
    // Utility functions.
    (void*)&ebpf_random_uint32,
    (void*)&_ebpf_core_get_time_since_boot_ns,
    (void*)&ebpf_get_current_cpu,
    (void*)&_ebpf_core_get_time_ns,
    (void*)&ebpf_core_csum_diff,
    // Ring buffer output.
    (void*)&ebpf_ring_buffer_map_output,
    (void*)&_ebpf_core_trace_printk2,
    (void*)&_ebpf_core_trace_printk3,
    (void*)&_ebpf_core_trace_printk4,
    (void*)&_ebpf_core_trace_printk5,
    (void*)&_ebpf_core_map_push_elem,
    (void*)&_ebpf_core_map_pop_elem,
    (void*)&_ebpf_core_map_peek_elem,
    (void*)&_ebpf_core_get_pid_tgid,
    (void*)&_ebpf_core_get_current_logon_id,
    (void*)&_ebpf_core_is_current_admin,
};

static ebpf_extension_provider_t* _ebpf_global_helper_function_provider_context = NULL;
static ebpf_helper_function_addresses_t _ebpf_global_helper_function_dispatch_table = {
    EBPF_COUNT_OF(_ebpf_general_helpers), (uint64_t*)_ebpf_general_helpers};
static ebpf_program_data_t _ebpf_global_helper_function_program_data = {
    &_ebpf_global_helper_program_info, &_ebpf_global_helper_function_dispatch_table};

static ebpf_extension_data_t _ebpf_global_helper_function_extension_data = {
    EBPF_CORE_GLOBAL_HELPER_EXTENSION_VERSION,
    sizeof(_ebpf_global_helper_function_program_data),
    &_ebpf_global_helper_function_program_data};

NTSTATUS
ebpf_general_helper_function_provider_attach_client(
    HANDLE nmr_binding_handle,
    _Inout_ void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Out_ void** provider_binding_context,
    _Out_ const void** provider_dispatch)
{
    UNREFERENCED_PARAMETER(nmr_binding_handle);
    UNREFERENCED_PARAMETER(provider_context);
    UNREFERENCED_PARAMETER(client_registration_instance);
    UNREFERENCED_PARAMETER(client_binding_context);
    UNREFERENCED_PARAMETER(client_dispatch);

    *provider_binding_context = NULL;
    *provider_dispatch = NULL;
    return STATUS_SUCCESS;
}

NTSTATUS
ebpf_general_helper_function_provider_detach_client(_Inout_ void* provider_binding_context)
{
    UNREFERENCED_PARAMETER(provider_binding_context);

    // There are no outstanding calls to the client dispatch table,
    // so return success synchronously.
    return STATUS_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_core_initiate()
{
    ebpf_result_t return_value;

    ebpf_program_information_extension_interface_id = EBPF_PROGRAM_INFO_EXTENSION_IID;
    ebpf_hook_extension_interface_id = EBPF_HOOK_EXTENSION_IID;

    return_value = ebpf_platform_initiate();
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_trace_initiate();
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_epoch_initiate();
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_state_initiate();
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_async_initiate();
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    ebpf_object_tracking_initiate();

    return_value = ebpf_pinning_table_allocate(&_ebpf_core_map_pinning_table);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_handle_table_initiate();
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_program_initiate();
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_native_initiate();
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    _ebpf_global_helper_program_info.count_of_program_type_specific_helpers = ebpf_core_helper_functions_count;
    _ebpf_global_helper_program_info.program_type_specific_helper_prototype = ebpf_core_helper_function_prototype;
    return_value = ebpf_provider_load(
        &_ebpf_global_helper_function_provider_context,
        &ebpf_program_information_extension_interface_id,
        &ebpf_general_helper_function_module_id,
        NULL,
        &_ebpf_global_helper_function_extension_data,
        NULL,
        NULL,
        (PNPI_PROVIDER_ATTACH_CLIENT_FN)ebpf_general_helper_function_provider_attach_client,
        (PNPI_PROVIDER_DETACH_CLIENT_FN)ebpf_general_helper_function_provider_detach_client,
        NULL);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_update_global_helpers(ebpf_core_helper_function_prototype, ebpf_core_helper_functions_count);
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

    ebpf_async_terminate();

    ebpf_pinning_table_free(_ebpf_core_map_pinning_table);
    _ebpf_core_map_pinning_table = NULL;

    ebpf_state_terminate();

    // Shut down the epoch tracker and free any remaining memory or work items.
    // Note: Some objects may only be released on epoch termination.
    ebpf_epoch_flush();
    ebpf_epoch_terminate();

    // Terminate native module. This is a blocking call and will return only when
    // all the native drivers have been detached and unloaded. Hence this needs
    // to be called after ebpf_epoch_terminate() to ensure all the program epoch
    // cleanup work items have been executed by this time.
    ebpf_native_terminate();

    // Verify that all ebpf_core_object_t objects have been freed.
    ebpf_object_tracking_terminate();

    ebpf_trace_terminate();

    ebpf_platform_terminate();
}

_Must_inspect_result_ ebpf_result_t
ebpf_core_load_code(
    ebpf_handle_t program_handle,
    ebpf_code_type_t code_type,
    _In_opt_ const void* code_context,
    _In_reads_(code_size) const uint8_t* code,
    size_t code_size)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;
    retval = ebpf_object_reference_by_handle(program_handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_program_load_code(program, code_type, code_context, code, code_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)program);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_load_code(_In_ const ebpf_operation_load_code_request_t* request)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    uint8_t* code = NULL;
    size_t code_length = 0;

    if (request->code_type == EBPF_CODE_NATIVE) {
        retval = EBPF_INVALID_ARGUMENT;
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_CORE,
            "code_type == EBPF_CODE_NATIVE can only be loaded through program driver");
        goto Done;
    }

    if (request->code_type == EBPF_CODE_JIT) {
        if (_ebpf_core_code_integrity_state == EBPF_CODE_INTEGRITY_HYPERVISOR_KERNEL_MODE) {
            retval = EBPF_BLOCKED_BY_POLICY;
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_CORE,
                "code_type == EBPF_CODE_JIT blocked by EBPF_CODE_INTEGRITY_HYPERVISOR_KERNEL_MODE");
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
ebpf_core_resolve_helper(
    ebpf_handle_t program_handle,
    const size_t count_of_helpers,
    _In_reads_(count_of_helpers) const uint32_t* helper_function_ids,
    _Out_writes_(count_of_helpers) uint64_t* helper_function_addresses)
{
    EBPF_LOG_ENTRY();
    ebpf_program_t* program = NULL;
    ebpf_result_t return_value =
        ebpf_object_reference_by_handle(program_handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_program_set_helper_function_ids(program, count_of_helpers, helper_function_ids);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_program_get_helper_function_addresses(program, count_of_helpers, helper_function_addresses);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)program);
    EBPF_RETURN_RESULT(return_value);
}

static ebpf_result_t
_ebpf_core_protocol_resolve_helper(
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

    if (count_of_helpers == 0) {
        goto Done;
    }

    request_helper_ids = (uint32_t*)ebpf_allocate_with_tag(count_of_helpers * sizeof(uint32_t), EBPF_POOL_TAG_CORE);
    if (request_helper_ids == NULL) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }
    for (helper_index = 0; helper_index < count_of_helpers; helper_index++) {
        request_helper_ids[helper_index] = request->helper_id[helper_index];
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
ebpf_core_resolve_maps(
    ebpf_handle_t program_handle,
    uint32_t count_of_maps,
    _In_reads_(count_of_maps) const ebpf_handle_t* map_handles,
    _Out_writes_(count_of_maps) uintptr_t* map_addresses)
{
    EBPF_LOG_ENTRY();
    ebpf_program_t* program = NULL;
    uint32_t map_index = 0;

    ebpf_result_t return_value =
        ebpf_object_reference_by_handle(program_handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    for (map_index = 0; map_index < count_of_maps; map_index++) {
        ebpf_map_t* map;
        return_value =
            ebpf_object_reference_by_handle(map_handles[map_index], EBPF_OBJECT_MAP, (ebpf_core_object_t**)&map);

        if (return_value != EBPF_SUCCESS) {
            goto Done;
        }

        map_addresses[map_index] = (uint64_t)map;
    }

    return_value = ebpf_program_associate_maps(program, (ebpf_map_t**)map_addresses, count_of_maps);

Done:
    // Release our reference only after the map has been associated with the program.
    for (uint32_t map_index2 = 0; map_index2 < map_index; map_index2++) {
        ebpf_object_release_reference((ebpf_core_object_t*)map_addresses[map_index2]);
    }

    ebpf_object_release_reference((ebpf_core_object_t*)program);
    EBPF_RETURN_RESULT(return_value);
}

static ebpf_result_t
_ebpf_core_protocol_resolve_map(
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

_Must_inspect_result_ ebpf_result_t
ebpf_core_create_map(
    _In_ const ebpf_utf8_string_t* map_name,
    _In_ const ebpf_map_definition_in_memory_t* ebpf_map_definition,
    ebpf_handle_t inner_map_handle,
    _Out_ ebpf_handle_t* map_handle)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;

    retval = ebpf_map_create(map_name, ebpf_map_definition, inner_map_handle, &map);
    if (retval != EBPF_SUCCESS) {
        return retval;
    }

    ebpf_core_object_t* map_object = (ebpf_core_object_t*)map;

    retval = ebpf_handle_create(map_handle, (ebpf_base_object_t*)map_object);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = EBPF_SUCCESS;

Done:
    ebpf_object_release_reference(map_object);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_create_map(
    _In_ const struct _ebpf_operation_create_map_request* request,
    _Inout_ struct _ebpf_operation_create_map_reply* reply)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_utf8_string_t map_name = {0};

    if (request->header.length > EBPF_OFFSET_OF(ebpf_operation_create_map_request_t, data)) {
        map_name.value = (uint8_t*)request->data;
        map_name.length = ((uint8_t*)request) + request->header.length - ((uint8_t*)request->data);
    }

    retval = ebpf_core_create_map(&map_name, &request->ebpf_map_definition, request->inner_map_handle, &reply->handle);

    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_create_program(
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

static ebpf_result_t
_ebpf_core_protocol_load_native_module(
    _In_ const ebpf_operation_load_native_module_request_t* request,
    _Out_ ebpf_operation_load_native_module_reply_t* reply)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    size_t service_name_length = 0;

    result = ebpf_safe_size_t_subtract(
        request->header.length,
        EBPF_OFFSET_OF(ebpf_operation_load_native_module_request_t, data),
        &service_name_length);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Service name is wide char
    if (service_name_length % 2 != 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    result = ebpf_native_load(
        (wchar_t*)request->data,
        (uint16_t)service_name_length,
        &request->module_id,
        &reply->native_module_handle,
        &reply->count_of_maps,
        &reply->count_of_programs);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_core_protocol_load_native_programs(
    _In_ const ebpf_operation_load_native_programs_request_t* request,
    _Inout_updates_bytes_(reply_length) ebpf_operation_load_native_programs_reply_t* reply,
    uint16_t reply_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_handle_t* map_handles = NULL;
    size_t count_of_map_handles = 0;
    ebpf_handle_t* program_handles = NULL;
    size_t count_of_program_handles = 0;
    size_t required_reply_length = 0;
    size_t map_handles_size = 0;
    size_t program_handles_size = 0;

    // Validate that the reply length is sufficient.
    result = ebpf_native_get_count_of_maps(&request->module_id, &count_of_map_handles);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    result = ebpf_native_get_count_of_programs(&request->module_id, &count_of_program_handles);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    if (count_of_program_handles == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    result = ebpf_safe_size_t_multiply(count_of_map_handles, sizeof(ebpf_handle_t), &map_handles_size);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }
    result = ebpf_safe_size_t_multiply(count_of_program_handles, sizeof(ebpf_handle_t), &program_handles_size);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    result = ebpf_safe_size_t_add(map_handles_size, program_handles_size, &required_reply_length);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }
    result = ebpf_safe_size_t_add(
        EBPF_OFFSET_OF(ebpf_operation_load_native_programs_reply_t, data),
        required_reply_length,
        &required_reply_length);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    if (reply_length < required_reply_length) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (count_of_map_handles) {
        map_handles = ebpf_allocate_with_tag(sizeof(ebpf_handle_t) * count_of_map_handles, EBPF_POOL_TAG_CORE);
        if (map_handles == NULL) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }
    }

    program_handles = ebpf_allocate_with_tag(sizeof(ebpf_handle_t) * count_of_program_handles, EBPF_POOL_TAG_CORE);
    if (program_handles == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    result = ebpf_native_load_programs(
        &request->module_id, count_of_map_handles, map_handles, count_of_program_handles, program_handles);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    reply->map_handle_count = count_of_map_handles;
    reply->program_handle_count = count_of_program_handles;

    if (map_handles) {
        memcpy(reply->data, map_handles, map_handles_size);
    }
    memcpy(reply->data + map_handles_size, program_handles, program_handles_size);

Done:
    ebpf_free(map_handles);
    ebpf_free(program_handles);

    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_core_protocol_map_find_element(
    _In_ const ebpf_operation_map_find_element_request_t* request,
    _Inout_ ebpf_operation_map_find_element_reply_t* reply,
    uint16_t reply_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    size_t value_length;
    size_t key_length;

    retval = ebpf_object_reference_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_core_object_t**)&map);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(ebpf_operation_map_find_element_request_t, key), &key_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_safe_size_t_subtract(
        reply_length, EBPF_OFFSET_OF(ebpf_operation_map_find_element_reply_t, value), &value_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_map_find_entry(
        map,
        key_length,
        request->key,
        value_length,
        reply->value,
        request->find_and_delete ? EPBF_MAP_FIND_FLAG_DELETE : 0);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = EBPF_SUCCESS;
    reply->header.length = reply_length;

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)map);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_map_update_element(_In_ const ebpf_operation_map_update_element_request_t* request)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    size_t value_length;
    size_t key_length;

    retval = ebpf_object_reference_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_core_object_t**)&map);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    const ebpf_map_definition_in_memory_t* map_definition = ebpf_map_get_definition(map);

    retval = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(ebpf_operation_map_update_element_request_t, data), &value_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_safe_size_t_subtract(value_length, map_definition->key_size, &value_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    key_length = map_definition->key_size;

    retval = ebpf_map_update_entry(
        map, key_length, request->data, value_length, request->data + key_length, request->option, 0);

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)map);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_map_update_element_with_handle(
    _In_ const ebpf_operation_map_update_element_with_handle_request_t* request)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    size_t key_length;

    retval = ebpf_object_reference_by_handle(request->map_handle, EBPF_OBJECT_MAP, (ebpf_core_object_t**)&map);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_safe_size_t_subtract(
        request->header.length,
        EBPF_OFFSET_OF(ebpf_operation_map_update_element_with_handle_request_t, key),
        &key_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_map_update_entry_with_handle(map, key_length, request->key, request->value_handle, request->option);

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)map);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_map_delete_element(_In_ const ebpf_operation_map_delete_element_request_t* request)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    size_t key_length;

    retval = ebpf_object_reference_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_core_object_t**)&map);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(ebpf_operation_map_delete_element_request_t, key), &key_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_map_delete_entry(map, key_length, request->key, 0);

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)map);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_map_get_next_key(
    _In_ const ebpf_operation_map_get_next_key_request_t* request,
    _Inout_ ebpf_operation_map_get_next_key_reply_t* reply,
    uint16_t reply_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_map_t* map = NULL;
    size_t previous_key_length;
    size_t next_key_length;

    retval = ebpf_object_reference_by_handle(request->handle, EBPF_OBJECT_MAP, (ebpf_core_object_t**)&map);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_safe_size_t_subtract(
        request->header.length,
        EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key),
        &previous_key_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_safe_size_t_subtract(
        reply_length, EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_reply_t, next_key), &next_key_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    const ebpf_map_definition_in_memory_t* map_definition = ebpf_map_get_definition(map);

    if (previous_key_length != 0 && previous_key_length != map_definition->key_size) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (next_key_length != map_definition->key_size) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    retval = ebpf_map_next_key(
        map, next_key_length, previous_key_length == 0 ? NULL : request->previous_key, reply->next_key);

    reply->header.length = reply_length;

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)map);

    EBPF_RETURN_RESULT(retval);
}

/**
 * @brief Complete the test run of an eBPF program. This is called when a program test run has completed. This
 * function will build the reply message and send it to the client.
 *
 * @param[in] result The result of the test run.
 * @param[in] program Program that was tested.
 * @param[in] options Results of the test run.
 * @param[in] completion_context The reply message to send to the client.
 * @param[in] async_context Handle to the async operation to complete.
 */
static void
_ebpf_core_protocol_program_test_run_complete(
    _In_ ebpf_result_t result,
    _In_ const ebpf_program_t* program,
    _In_ const ebpf_program_test_run_options_t* options,
    _Inout_ void* completion_context,
    _Inout_ void* async_context)
{
    ebpf_operation_program_test_run_reply_t* reply = (ebpf_operation_program_test_run_reply_t*)completion_context;
    if (result == EBPF_SUCCESS) {
        reply->header.length = (uint16_t)(
            EBPF_OFFSET_OF(ebpf_operation_program_test_run_reply_t, data) + options->data_size_out +
            options->context_size_out);
        reply->return_value = options->return_value;
        reply->context_offset = (uint16_t)options->data_size_out;
        reply->duration = options->duration;
    }

    ebpf_async_complete(async_context, reply->header.length, result);
    ebpf_object_release_reference((ebpf_core_object_t*)program);
    ebpf_free((void*)options);
}

static ebpf_result_t
_ebpf_core_protocol_program_test_run(
    _In_ const ebpf_operation_program_test_run_request_t* request,
    _Inout_updates_bytes_(reply_length) ebpf_operation_program_test_run_reply_t* reply,
    uint16_t reply_length,
    _Inout_ void* async_context)
{
    EBPF_LOG_ENTRY();

    ebpf_program_test_run_options_t* options = NULL;

    ebpf_result_t retval;
    ebpf_program_t* program = NULL;
    size_t data_in_end;

    // Validate that the request is large enough to contain the context_offset.
    retval = ebpf_safe_size_t_add(
        EBPF_OFFSET_OF(ebpf_operation_program_test_run_request_t, data), request->context_offset, &data_in_end);

    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    if (data_in_end > request->header.length) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    retval =
        ebpf_object_reference_by_handle(request->program_handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    options = (ebpf_program_test_run_options_t*)ebpf_allocate(sizeof(ebpf_program_test_run_options_t));
    if (!options) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    options->data_size_in = request->context_offset;
    options->context_size_in = (size_t)(request->header.length) - data_in_end;
    options->context_size_out = options->context_size_in;
    options->data_size_out = (size_t)reply_length - EBPF_OFFSET_OF(ebpf_operation_program_test_run_reply_t, data) -
                             options->context_size_out;
    options->repeat_count = request->repeat_count;
    options->flags = request->flags;
    options->cpu = request->cpu;
    options->batch_size = request->batch_size;
    options->data_in = options->data_size_in ? request->data : NULL;
    options->context_in = options->context_size_in ? request->data + request->context_offset : NULL;
    options->data_out = options->data_size_out ? reply->data : NULL;
    options->context_out = options->context_size_out ? reply->data + options->data_size_out : NULL;

    retval = ebpf_program_execute_test_run(
        program, options, async_context, reply, _ebpf_core_protocol_program_test_run_complete);

Done:
    if (retval != EBPF_PENDING) {
        ebpf_free(options);
        ebpf_object_release_reference((ebpf_core_object_t*)program);
    }
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_query_program_info(
    _In_ const struct _ebpf_operation_query_program_info_request* request,
    _Inout_ struct _ebpf_operation_query_program_info_reply* reply,
    uint16_t reply_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;
    size_t required_reply_length;
    ebpf_utf8_string_t file_name = {0};
    ebpf_utf8_string_t section_name = {0};
    ebpf_code_type_t code_type;

    retval = ebpf_object_reference_by_handle(request->handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_program_get_program_file_name(program, &file_name);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_program_get_program_section_name(program, &section_name);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    code_type = ebpf_program_get_code_type(program);

    retval = ebpf_safe_size_t_add(section_name.length, file_name.length, &required_reply_length);
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
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    reply->file_name_offset = EBPF_OFFSET_OF(struct _ebpf_operation_query_program_info_reply, data);
    reply->section_name_offset = reply->file_name_offset + (uint16_t)file_name.length;

    memcpy(reply->data, file_name.value, file_name.length);
    memcpy(reply->data + file_name.length, section_name.value, section_name.length);
    reply->code_type = code_type;

    reply->header.length = (uint16_t)required_reply_length;

Done:
    ebpf_utf8_string_free(&file_name);
    ebpf_utf8_string_free(&section_name);

    ebpf_object_release_reference((ebpf_core_object_t*)program);

    EBPF_RETURN_RESULT(retval);
}

_Must_inspect_result_ ebpf_result_t
ebpf_core_update_pinning(const ebpf_handle_t handle, _In_ const ebpf_utf8_string_t* path)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval = EBPF_SUCCESS;
    ebpf_core_object_t* object = NULL;

    if (handle == UINT64_MAX) {
        retval = ebpf_pinning_table_delete(_ebpf_core_map_pinning_table, path);
        goto Done;
    } else {
        retval = ebpf_object_reference_by_handle(handle, EBPF_OBJECT_UNKNOWN, (ebpf_core_object_t**)&object);
        if (retval != EBPF_SUCCESS) {
            goto Done;
        }

        retval = ebpf_pinning_table_insert(_ebpf_core_map_pinning_table, path, (ebpf_core_object_t*)object);
    }
Done:
    ebpf_object_release_reference((ebpf_core_object_t*)object);

    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_update_pinning(_In_ const struct _ebpf_operation_update_map_pinning_request* request)
{
    EBPF_LOG_ENTRY();
    size_t path_length;
    ebpf_result_t retval = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(ebpf_operation_update_pinning_request_t, path), &path_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    const ebpf_utf8_string_t path = {(uint8_t*)request->path, path_length};

    if (path.length == 0) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    retval = ebpf_core_update_pinning(request->handle, &path);

Done:
    EBPF_RETURN_RESULT(retval);
}

_Must_inspect_result_ ebpf_result_t
ebpf_core_get_pinned_object(_In_ const ebpf_utf8_string_t* path, _Out_ ebpf_handle_t* handle)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_core_object_t* object = NULL;
    retval = ebpf_pinning_table_find(_ebpf_core_map_pinning_table, path, (ebpf_core_object_t**)&object);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_handle_create(handle, (ebpf_base_object_t*)object);

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)object);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_get_pinned_object(
    _In_ const struct _ebpf_operation_get_pinned_object_request* request,
    _Inout_ struct _ebpf_operation_get_pinned_object_reply* reply)
{
    EBPF_LOG_ENTRY();
    ebpf_core_object_t* object = NULL;
    size_t path_length;
    ebpf_result_t retval = ebpf_safe_size_t_subtract(
        request->header.length, EBPF_OFFSET_OF(ebpf_operation_get_pinned_object_request_t, path), &path_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    if (path_length == 0) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    const ebpf_utf8_string_t path = {(uint8_t*)request->path, path_length};
    retval = ebpf_core_get_pinned_object(&path, &reply->handle);

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)object);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_link_program(
    _In_ const ebpf_operation_link_program_request_t* request, _Inout_ ebpf_operation_link_program_reply_t* reply)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;
    ebpf_link_t* link = NULL;
    ebpf_code_type_t code_type;

    retval =
        ebpf_object_reference_by_handle(request->program_handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    code_type = ebpf_program_get_code_type(program);
    if (code_type == EBPF_CODE_NONE) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    retval = ebpf_link_create(&link);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    size_t data_length;
    retval = ebpf_safe_size_t_subtract(
        request->header.length, FIELD_OFFSET(ebpf_operation_link_program_request_t, data), &data_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }
    retval = ebpf_link_initialize(link, request->attach_type, request->data, data_length);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_link_attach_program(link, program);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_handle_create(&reply->link_handle, (ebpf_base_object_t*)link);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    if (retval != EBPF_SUCCESS && link) {
        ebpf_link_detach_program(link);
    }
    ebpf_object_release_reference((ebpf_core_object_t*)program);
    ebpf_object_release_reference((ebpf_core_object_t*)link);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_find_matching_link(
    ebpf_handle_t program_handle,
    _In_ const ebpf_attach_type_t* attach_type,
    _In_reads_bytes_(context_data_length) const uint8_t* context_data,
    size_t context_data_length,
    _Inout_opt_ ebpf_link_t* previous_link,
    _Outptr_ ebpf_link_t** link)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_core_object_t* previous_object = (ebpf_core_object_t*)previous_link;
    ebpf_link_t* local_link;
    uint16_t info_size = sizeof(struct bpf_link_info);
    size_t info_attach_data_size = sizeof(struct bpf_link_info) - FIELD_OFFSET(struct bpf_link_info, attach_data);

    if (context_data_length > info_attach_data_size) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    bool match_found = FALSE;

    *link = NULL;

    // Enumerate all link objects starting with previous_object.
    while (TRUE) {
        struct bpf_link_info info = {0};
        ebpf_object_reference_next_object(previous_object, EBPF_OBJECT_LINK, (ebpf_core_object_t**)&local_link);
        if (previous_object != NULL) {
            ebpf_object_release_reference(previous_object);
        }
        if (local_link == NULL) {
            // No more links.
            result = EBPF_NO_MORE_KEYS;
            break;
        }
        previous_object = (ebpf_core_object_t*)local_link;

        result = ebpf_link_get_info(local_link, (uint8_t*)&info, &info_size);
        if (result != EBPF_SUCCESS) {
            break;
        }

        // Compare attach type.
        if (memcmp(&info.attach_type_uuid, attach_type, sizeof(*attach_type)) != 0) {
            continue;
        }

        // Compare attach parameter.
        if (memcmp(&info.attach_data, context_data, context_data_length) != 0) {
            continue;
        }

        // Compare program id.
        if (program_handle != ebpf_handle_invalid) {
            ebpf_core_object_t* program = NULL;
            result = ebpf_object_reference_by_handle(program_handle, EBPF_OBJECT_PROGRAM, &program);
            if (result != EBPF_SUCCESS) {
                break;
            }
            if (info.prog_id != program->id) {
                ebpf_object_release_reference(program);
                continue;
            }
            ebpf_object_release_reference(program);
        }

        match_found = TRUE;
        break;
    }

    if (match_found) {
        *link = local_link;
    }

Exit:
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_core_protocol_unlink_program(_In_ const ebpf_operation_unlink_program_request_t* request)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval = EBPF_SUCCESS;
    ebpf_link_t* link = NULL;

    if (request->link_handle != ebpf_handle_invalid) {
        retval = ebpf_object_reference_by_handle(request->link_handle, EBPF_OBJECT_LINK, (ebpf_core_object_t**)&link);
        if (retval != EBPF_SUCCESS) {
            goto Done;
        }
    } else if (request->attach_data_present) {
        // This path will be taken for bpf_prog_detach and bpf_prog_detach2 APIs.
        // Find the link object matching the unlink request parameters.
        size_t data_length;
        ebpf_result_t return_value = ebpf_safe_size_t_subtract(
            request->header.length, FIELD_OFFSET(ebpf_operation_unlink_program_request_t, data), &data_length);
        if (return_value != EBPF_SUCCESS) {
            goto Done;
        }

        ebpf_link_t* previous_link = NULL;
        while (retval != EBPF_NO_MORE_KEYS) {
            retval = _ebpf_core_find_matching_link(
                request->program_handle, &request->attach_type, request->data, data_length, previous_link, &link);
            if (retval != EBPF_SUCCESS) {
                break;
            }
            // Detach the link. Since _ebpf_core_find_matching_link takes a reference on the link object,
            // the detach function will not free the link object.
            ebpf_link_detach_program(link);
            // Pass the link object as the previous object parameter to the _ebpf_core_find_matching_link function,
            // which will release the reference from it.
            previous_link = link;
        }
        if (retval == EBPF_NO_MORE_KEYS) {
            // No more matching links to detach.
            retval = EBPF_SUCCESS;
        }
    }

    if (link != NULL) {
        ebpf_link_detach_program(link);
    }

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)link);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_close_handle(_In_ const ebpf_operation_close_handle_request_t* request)
{
    EBPF_LOG_ENTRY();
    EBPF_RETURN_RESULT(ebpf_handle_close(request->handle));
}

static uint64_t
_ebpf_core_protocol_get_ec_function(
    _In_ const ebpf_operation_get_ec_function_request_t* request, _Inout_ ebpf_operation_get_ec_function_reply_t* reply)
{
    EBPF_LOG_ENTRY();
    if (request->function != EBPF_EC_FUNCTION_LOG) {
        return EBPF_INVALID_ARGUMENT;
    }

    reply->address = (uint64_t)ebpf_log_function;
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

// Get helper info for a program or program type.  This is used by the jitter/verifier,
// not by libbpf which instead uses ebpf_program_get_info
// to get standard cross-platform info.
static ebpf_result_t
_ebpf_core_protocol_get_program_info(
    _In_ const ebpf_operation_get_program_info_request_t* request,
    _Inout_ ebpf_operation_get_program_info_reply_t* reply,
    uint16_t reply_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;
    ebpf_program_parameters_t program_parameters = {0};
    ebpf_program_info_t* program_info = NULL;
    size_t serialization_buffer_size;
    size_t required_length;

    program_parameters.program_type = request->program_type;

    if (request->program_handle == ebpf_handle_invalid) {
        retval = ebpf_program_create(&program);
        if (retval != EBPF_SUCCESS) {
            goto Done;
        }
        retval = ebpf_program_initialize(program, &program_parameters);
        if (retval != EBPF_SUCCESS) {
            goto Done;
        }
    } else {
        retval = ebpf_object_reference_by_handle(
            request->program_handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program);
        if (retval != EBPF_SUCCESS) {
            goto Done;
        }
    }

    retval = ebpf_program_get_program_info(program, &program_info);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    ebpf_assert(program_info);

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
    ebpf_object_release_reference((ebpf_core_object_t*)program);
    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_core_protocol_convert_pinning_entries_to_map_info_array(
    uint16_t entry_count,
    _In_reads_(entry_count) ebpf_pinning_entry_t* pinning_entries,
    _Outptr_result_buffer_all_(entry_count) ebpf_map_info_internal_t** map_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_map_info_internal_t* local_map_info = NULL;
    uint16_t index;
    size_t allocation_size = sizeof(ebpf_map_info_internal_t) * entry_count;

    ebpf_assert(map_info);
    ebpf_assert(entry_count);
    ebpf_assert(pinning_entries);

    local_map_info = (ebpf_map_info_internal_t*)ebpf_allocate_with_tag(allocation_size, EBPF_POOL_TAG_CORE);
    if (local_map_info == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    for (index = 0; index < entry_count; index++) {
        ebpf_pinning_entry_t* source = &pinning_entries[index];
        ebpf_map_info_internal_t* destination = &local_map_info[index];

        ebpf_assert(ebpf_object_get_type(source->object) == EBPF_OBJECT_MAP);

        // Query map defintion.
        const ebpf_map_definition_in_memory_t* map_definition = ebpf_map_get_definition((ebpf_map_t*)source->object);
        destination->definition = *map_definition;
        destination->definition.value_size = ebpf_map_get_effective_value_size((ebpf_map_t*)source->object);
        // Set pin path. No need to duplicate.
        destination->pin_path = source->path;
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
    _Out_ ebpf_operation_get_pinned_map_info_reply_t* map_info_reply)
{
    ebpf_result_t result = EBPF_SUCCESS;
    size_t serialization_buffer_size;
    size_t required_serialization_length;

    serialization_buffer_size = output_buffer_length - EBPF_OFFSET_OF(ebpf_operation_get_pinned_map_info_reply_t, data);

    result = ebpf_serialize_internal_map_info_array(
        map_count,
        map_info,
        map_info_reply->data,
        (const size_t)serialization_buffer_size,
        &map_info_reply->size,
        &required_serialization_length);

    if (result != EBPF_SUCCESS) {
        map_info_reply->header.length = (uint16_t)(
            required_serialization_length + EBPF_OFFSET_OF(ebpf_operation_get_pinned_map_info_reply_t, data));
    } else {
        map_info_reply->map_count = map_count;
    }

    return result;
}

// Get map pinning info, as opposed to ebpf_map_get_info
// which is used by libbpf to get standard cross-platform bpf_map_info.
static ebpf_result_t
_ebpf_core_protocol_get_pinned_map_info(
    _In_ const ebpf_operation_get_pinned_map_info_request_t* request,
    _Inout_ ebpf_operation_get_pinned_map_info_reply_t* reply,
    uint16_t reply_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    uint16_t entry_count = 0;
    ebpf_pinning_entry_t* pinning_entries = NULL;
    ebpf_map_info_internal_t* map_info = NULL;

    UNREFERENCED_PARAMETER(request);

    // Enumerate all the pinning entries for map objects.
    result = ebpf_pinning_table_enumerate_entries(
        _ebpf_core_map_pinning_table, EBPF_OBJECT_MAP, &entry_count, &pinning_entries);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (entry_count == 0 || !pinning_entries) {
        // No pinned map entries to return.
        goto Exit;
    }

    // Convert pinning entries to map_info_t array.
    result = _ebpf_core_protocol_convert_pinning_entries_to_map_info_array(entry_count, pinning_entries, &map_info);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    _Analysis_assume_(map_info != NULL);

    // Serialize map info array onto reply structure.
    _Analysis_assume_(map_info != NULL);
    result = _ebpf_core_protocol_serialize_map_info_reply(entry_count, map_info, reply_length, reply);

Exit:

    ebpf_free(map_info);
    ebpf_pinning_entries_release(entry_count, pinning_entries);

    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_core_get_handle_by_id(ebpf_object_type_t type, ebpf_id_t id, _Out_ ebpf_handle_t* handle)
{
    EBPF_LOG_ENTRY();
    ebpf_core_object_t* object;
    ebpf_result_t result = ebpf_object_reference_by_id(id, type, &object);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    result = ebpf_handle_create(handle, (ebpf_base_object_t*)object);
    ebpf_object_release_reference(object);

    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_get_handle_by_id(
    ebpf_object_type_t type,
    _In_ const ebpf_operation_get_handle_by_id_request_t* request,
    _Out_ ebpf_operation_get_handle_by_id_reply_t* reply)
{
    reply->header.length = sizeof(*reply);
    ebpf_result_t result = ebpf_core_get_handle_by_id(type, request->id, &reply->handle);

    return result;
}

static ebpf_result_t
_ebpf_core_protocol_get_map_handle_by_id(
    _In_ const ebpf_operation_get_handle_by_id_request_t* request, _Out_ ebpf_operation_get_handle_by_id_reply_t* reply)
{
    EBPF_LOG_ENTRY();
    EBPF_RETURN_RESULT(_get_handle_by_id(EBPF_OBJECT_MAP, request, reply));
}

static ebpf_result_t
_ebpf_core_protocol_get_program_handle_by_id(
    _In_ const ebpf_operation_get_handle_by_id_request_t* request, _Out_ ebpf_operation_get_handle_by_id_reply_t* reply)
{
    EBPF_LOG_ENTRY();
    EBPF_RETURN_RESULT(_get_handle_by_id(EBPF_OBJECT_PROGRAM, request, reply));
}

static ebpf_result_t
_ebpf_core_protocol_get_link_handle_by_id(
    _In_ const ebpf_operation_get_handle_by_id_request_t* request, _Out_ ebpf_operation_get_handle_by_id_reply_t* reply)
{
    return _get_handle_by_id(EBPF_OBJECT_LINK, request, reply);
}

static ebpf_result_t
_get_next_id(
    ebpf_object_type_t type,
    _In_ const ebpf_operation_get_next_id_request_t* request,
    _Out_ ebpf_operation_get_next_id_reply_t* reply)
{
    EBPF_RETURN_RESULT(ebpf_object_get_next_id(request->start_id, type, &reply->next_id));
}

static ebpf_result_t
_ebpf_core_protocol_get_next_link_id(
    _In_ const ebpf_operation_get_next_id_request_t* request, _Out_ ebpf_operation_get_next_id_reply_t* reply)
{
    EBPF_LOG_ENTRY();
    EBPF_RETURN_RESULT(_get_next_id(EBPF_OBJECT_LINK, request, reply));
}

static ebpf_result_t
_ebpf_core_protocol_get_next_map_id(
    _In_ const ebpf_operation_get_next_id_request_t* request, _Out_ ebpf_operation_get_next_id_reply_t* reply)
{
    EBPF_LOG_ENTRY();
    EBPF_RETURN_RESULT(_get_next_id(EBPF_OBJECT_MAP, request, reply));
}

static ebpf_result_t
_ebpf_core_protocol_get_next_program_id(
    _In_ const ebpf_operation_get_next_id_request_t* request, _Out_ ebpf_operation_get_next_id_reply_t* reply)
{
    EBPF_LOG_ENTRY();
    EBPF_RETURN_RESULT(_get_next_id(EBPF_OBJECT_PROGRAM, request, reply));
}

static ebpf_result_t
_ebpf_core_protocol_get_next_pinned_program_path(
    _In_ const ebpf_operation_get_next_pinned_program_path_request_t* request,
    _Out_ ebpf_operation_get_next_pinned_program_path_reply_t* reply,
    uint16_t reply_length)
{
    EBPF_LOG_ENTRY();
    ebpf_utf8_string_t start_path;
    ebpf_utf8_string_t next_path;

    size_t path_length;
    ebpf_result_t result = ebpf_safe_size_t_subtract(
        request->header.length,
        EBPF_OFFSET_OF(ebpf_operation_get_next_pinned_program_path_request_t, start_path),
        &path_length);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }
    start_path.length = path_length;
    start_path.value = (uint8_t*)request->start_path;
    next_path.length = reply_length - EBPF_OFFSET_OF(ebpf_operation_get_next_pinned_program_path_reply_t, next_path);
    next_path.value = (uint8_t*)reply->next_path;

    result =
        ebpf_pinning_table_get_next_path(_ebpf_core_map_pinning_table, EBPF_OBJECT_PROGRAM, &start_path, &next_path);

    if (result == EBPF_SUCCESS) {
        reply->header.length =
            (uint16_t)next_path.length + EBPF_OFFSET_OF(ebpf_operation_get_next_pinned_program_path_reply_t, next_path);
    }
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_core_protocol_bind_map(_In_ const ebpf_operation_bind_map_request_t* request)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_program_t* program = NULL;
    ebpf_map_t* map = NULL;

    result =
        ebpf_object_reference_by_handle(request->program_handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    result = ebpf_object_reference_by_handle(request->map_handle, EBPF_OBJECT_MAP, (ebpf_core_object_t**)&map);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    result = ebpf_program_associate_additional_map(program, map);

Done:
    if (program) {
        ebpf_object_release_reference((ebpf_core_object_t*)program);
    }
    if (map) {
        ebpf_object_release_reference((ebpf_core_object_t*)map);
    }
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_core_protocol_get_object_info(
    _In_ const ebpf_operation_get_object_info_request_t* request,
    _Out_ ebpf_operation_get_object_info_reply_t* reply,
    uint16_t reply_length)
{
    EBPF_LOG_ENTRY();
    uint16_t info_size = reply_length - FIELD_OFFSET(ebpf_operation_get_object_info_reply_t, info);

    ebpf_core_object_t* object;
    ebpf_result_t result = ebpf_object_reference_by_handle(request->handle, EBPF_OBJECT_UNKNOWN, &object);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    // List of object types is fixed at compile time.
    switch (object->type) {
    case EBPF_OBJECT_LINK:
        result = ebpf_link_get_info((ebpf_link_t*)object, reply->info, &info_size);
        break;
    case EBPF_OBJECT_MAP:
        result = ebpf_map_get_info((ebpf_map_t*)object, reply->info, &info_size);
        break;
    case EBPF_OBJECT_PROGRAM:
        result = ebpf_program_get_info((ebpf_program_t*)object, request->info, reply->info, &info_size);
        break;
    }

    if (result == EBPF_SUCCESS) {
        reply->header.length = FIELD_OFFSET(ebpf_operation_get_object_info_reply_t, info) + info_size;
    }
    ebpf_object_release_reference(object);
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_core_protocol_ring_buffer_map_query_buffer(
    _In_ const ebpf_operation_ring_buffer_map_query_buffer_request_t* request,
    _Out_ ebpf_operation_ring_buffer_map_query_buffer_reply_t* reply)
{
    EBPF_LOG_ENTRY();

    ebpf_map_t* map = NULL;
    ebpf_result_t result =
        ebpf_object_reference_by_handle(request->map_handle, EBPF_OBJECT_MAP, (ebpf_core_object_t**)&map);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (ebpf_map_get_definition(map)->type != BPF_MAP_TYPE_RINGBUF) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    result = ebpf_ring_buffer_map_query_buffer(map, (uint8_t**)(uintptr_t*)&reply->buffer_address);

Exit:
    ebpf_object_release_reference((ebpf_core_object_t*)map);
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_core_protocol_ring_buffer_map_async_query(
    _In_ const ebpf_operation_ring_buffer_map_async_query_request_t* request,
    _Inout_ ebpf_operation_ring_buffer_map_async_query_reply_t* reply,
    uint16_t reply_length,
    _Inout_ void* async_context)
{
    UNREFERENCED_PARAMETER(reply_length);

    ebpf_map_t* map = NULL;
    bool reference_taken = FALSE;

    ebpf_result_t result =
        ebpf_object_reference_by_handle(request->map_handle, EBPF_OBJECT_MAP, (ebpf_core_object_t**)&map);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    reference_taken = TRUE;

    if (ebpf_map_get_definition(map)->type != BPF_MAP_TYPE_RINGBUF) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Return buffer already consumed by caller in previous notification.
    result = ebpf_ring_buffer_map_return_buffer(map, request->consumer_offset);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    reply->header.id = EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY;
    reply->header.length = sizeof(ebpf_operation_ring_buffer_map_async_query_reply_t);
    result = ebpf_ring_buffer_map_async_query(map, &reply->async_query_result, async_context);

Exit:
    if (reference_taken) {
        ebpf_object_release_reference((ebpf_core_object_t*)map);
    }
    return result;
}

static void*
_ebpf_core_map_find_element(ebpf_map_t* map, const uint8_t* key)
{
    ebpf_result_t retval;
    uint8_t* value;
    retval = ebpf_map_find_entry(map, 0, key, sizeof(&value), (uint8_t*)&value, EBPF_MAP_FLAG_HELPER);
    if (retval != EBPF_SUCCESS) {
        return NULL;
    } else {
        return value;
    }
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

static void*
_ebpf_core_map_find_and_delete_element(_Inout_ ebpf_map_t* map, _In_ const uint8_t* key)
{
    ebpf_result_t retval;
    uint8_t* value;
    retval = ebpf_map_find_entry(
        map, 0, key, sizeof(&value), (uint8_t*)&value, EBPF_MAP_FLAG_HELPER | EPBF_MAP_FIND_FLAG_DELETE);
    if (retval != EBPF_SUCCESS) {
        return NULL;
    } else {
        return value;
    }
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
    // ebpf_query_time_since_boot returns time elapsed since
    // boot in units of 100 ns.
    return ebpf_query_time_since_boot(true) * EBPF_NS_PER_FILETIME;
}

static uint64_t
_ebpf_core_get_time_ns()
{
    // ebpf_query_time_since_boot returns time elapsed since
    // boot in units of 100 ns.
    return ebpf_query_time_since_boot(false) * EBPF_NS_PER_FILETIME;
}

static uint64_t
_ebpf_core_get_pid_tgid()
{
    return ((uint64_t)ebpf_platform_process_id() << 32) | ebpf_platform_thread_id();
}

static uint64_t
_ebpf_core_get_current_logon_id(_In_ const void* ctx)
{
    uint64_t logon_id = 0;

    UNREFERENCED_PARAMETER(ctx);

    if (!ebpf_is_preemptible()) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_CORE, "get_current_logon_id: Called at DISPATCH.");

        return 0;
    }

    ebpf_result_t result = ebpf_platform_get_authentication_id(&logon_id);
    if (result != EBPF_SUCCESS) {
        return 0;
    }

    return logon_id;
}

static int32_t
_ebpf_core_is_current_admin(_In_ const void* ctx)
{
    // TODO: Issue# 1871 - Implement this function.
    UNREFERENCED_PARAMETER(ctx);

    return -1;
}

// Pick a limit on string size based on the size of the eBPF stack.
#define MAX_PRINTK_STRING_SIZE 512

// Only integers are currently supported.
#define PRINTK_SPECIFIER_CHARS "diux"

static long
_ebpf_core_trace_printk(_In_reads_(fmt_size) const char* fmt, size_t fmt_size, int arg_count, ...)
{
    if (fmt_size > MAX_PRINTK_STRING_SIZE - 1) {
        // Disallow large fmt_size values.
        return -1;
    }

    // Make a copy of the original format string.
    char* output = (char*)ebpf_allocate_with_tag(fmt_size + 1, EBPF_POOL_TAG_CORE);
    if (output == NULL) {
        return -1;
    }
    memcpy(output, fmt, fmt_size);

    // Make sure the output is null-terminated, and
    // remove the newline if present.
    // A well-formed input should be null terminated,
    // so look at the next-to-last byte.
    char* end = output + fmt_size - 2;
    if (*end != '\n') {
        end++;
    }
    *end = '\0';

    /* Validate format string.
     * The conversion specifiers are limited to:
     * %d, %i, %u, %x, %ld, %li, %lu, %lx, %lld, %lli, %llu, %llx.
     * No modifier (size of field, padding with zeroes, etc.) is available.
     */
    long bytes_written = -1;
    const char* p;
    int specifier_count = 0;
    for (p = output; *p; p++) {
        if (*p != '%') {
            continue;
        }
        if (p[1] == 0) {
            break;
        }
        if (p[1] == '%') {
            // Allow a %% escape.
            p++;
            continue;
        }

        // We found a specifier.  Verify that it is in the legal set.
        if (strchr(PRINTK_SPECIFIER_CHARS, p[1])) {
            // We found a legal one character specifier.
            p++;
            specifier_count++;
            continue;
        }

        if (p[1] != 'l' || p[2] == 0) {
            break;
        }
        if (strchr(PRINTK_SPECIFIER_CHARS, p[2])) {
            // We found a legal two character specifier.
            p += 2;
            specifier_count++;
            continue;
        }

        if (p[2] != 'l' || p[3] == 0) {
            break;
        }
        if (strchr(PRINTK_SPECIFIER_CHARS, p[3])) {
            // We found a legal three character specifier.
            p += 3;
            specifier_count++;
            continue;
        }
        break;
    }

    if ((*p == 0) && (arg_count == specifier_count)) {
        va_list arg_list;
        __va_start(&arg_list, arg_count);
        bytes_written = ebpf_platform_printk(output, arg_list);
        __va_end(&arg_list);
    }

    ebpf_free(output);
    return bytes_written;
}

long
_ebpf_core_trace_printk2(_In_reads_(fmt_size) const char* fmt, size_t fmt_size)
{
    return _ebpf_core_trace_printk(fmt, fmt_size, 0);
}

long
_ebpf_core_trace_printk3(_In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3)
{
    return _ebpf_core_trace_printk(fmt, fmt_size, 1, arg3);
}

long
_ebpf_core_trace_printk4(_In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3, uint64_t arg4)
{
    return _ebpf_core_trace_printk(fmt, fmt_size, 2, arg3, arg4);
}

long
_ebpf_core_trace_printk5(
    _In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
    return _ebpf_core_trace_printk(fmt, fmt_size, 3, arg3, arg4, arg5);
}

int
ebpf_core_csum_diff(
    _In_reads_bytes_opt_(from_size) const void* from,
    int from_size,
    _In_reads_bytes_opt_(to_size) const void* to,
    int to_size,
    int seed)
{
    int csum_diff = -EINVAL;

    if ((from_size % 4 != 0) || (to_size % 4 != 0)) {
        // size of buffers should be a multiple of 4.
        goto Exit;
    }

    csum_diff = seed;
    if (to != NULL) {
        for (int i = 0; i < to_size / 2; i++) {
            csum_diff += (uint16_t)(*((uint16_t*)to + i));
        }
    }
    if (from != NULL) {
        for (int i = 0; i < from_size / 2; i++) {
            csum_diff += (uint16_t)(~*((uint16_t*)from + i));
        }
    }

    // Adding 16-bit unsigned integers or their one's complement will produce a positive 32-bit integer,
    // unless the length of the buffers is so long, that the signed 32 bit output overflows and produces a negative
    // result.
    if (csum_diff < 0) {
        csum_diff = -EINVAL;
    }
Exit:
    return csum_diff;
}

static int
_ebpf_core_ring_buffer_output(
    _Inout_ ebpf_map_t* map, _In_reads_bytes_(length) uint8_t* data, size_t length, uint64_t flags)
{
    // This function implements bpf_ringbuf_output helper function, which returns negative error in case of failure.
    UNREFERENCED_PARAMETER(flags);
    return -ebpf_ring_buffer_map_output(map, data, length);
}

static uint64_t
_ebpf_core_map_push_elem(_Inout_ ebpf_map_t* map, _In_ const uint8_t* value, uint64_t flags)
{
    return -ebpf_map_push_entry(map, 0, value, (int)flags | EBPF_MAP_FLAG_HELPER);
}

static uint64_t
_ebpf_core_map_pop_elem(_Inout_ ebpf_map_t* map, _Out_ uint8_t* value)
{
    return -ebpf_map_pop_entry(map, 0, value, EBPF_MAP_FLAG_HELPER);
}

static uint64_t
_ebpf_core_map_peek_elem(_Inout_ ebpf_map_t* map, _Out_ uint8_t* value)
{
    return -ebpf_map_peek_entry(map, 0, value, EBPF_MAP_FLAG_HELPER);
}

typedef enum _ebpf_protocol_call_type
{
    EBPF_PROTOCOL_FIXED_REQUEST_NO_REPLY,
    EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY,
    EBPF_PROTOCOL_FIXED_REQUEST_VARIABLE_REPLY,
    EBPF_PROTOCOL_VARIABLE_REQUEST_NO_REPLY,
    EBPF_PROTOCOL_VARIABLE_REQUEST_FIXED_REPLY,
    EBPF_PROTOCOL_VARIABLE_REQUEST_VARIABLE_REPLY,
    EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY_ASYNC,
    EBPF_PROTOCOL_VARIABLE_REQUEST_VARIABLE_REPLY_ASYNC,
} ebpf_protocol_call_type_t;

typedef struct _ebpf_protocol_handler
{
    // Determines which branch of the union is valid.
    ebpf_protocol_call_type_t call_type;
    union
    {
        void* default_case;
        ebpf_result_t(__cdecl* protocol_handler_no_reply)(_In_ const ebpf_operation_header_t* request);
        ebpf_result_t(__cdecl* protocol_handler_with_fixed_reply)(
            _In_ const ebpf_operation_header_t* request, _Out_ ebpf_operation_header_t* reply);
        ebpf_result_t(__cdecl* protocol_handler_with_variable_reply)(
            _In_ _In_ const ebpf_operation_header_t* request,
            _Out_writes_bytes_(output_buffer_length) ebpf_operation_header_t* reply,
            uint16_t output_buffer_length);
        ebpf_result_t(__cdecl* async_protocol_handler_with_reply)(
            _In_ const ebpf_operation_header_t* request,
            _Out_writes_bytes_(output_buffer_length) ebpf_operation_header_t* reply,
            uint16_t output_buffer_length,
            _Inout_ void* async_context);
    } dispatch;
    size_t minimum_request_size;
    size_t minimum_reply_size;
    union
    {
        uint64_t value;
        struct
        {
            uint64_t used_by_native : 1;
            uint64_t used_by_jit : 1;
            uint64_t used_by_interpret : 1;
        } bits;
    } flags;

} const ebpf_protocol_handler_t;

#define PROTOCOL_NATIVE_MODE 1
#define PROTOCOL_JIT_MODE 2
#define PROTOCOL_INTERPRET_MODE 4
#define PROTOCOL_JIT_OR_INTERPRET_MODE 6
#define PROTOCOL_ALL_MODES 7

#define DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_NO_REPLY(OPERATION, FLAGS)             \
    {                                                                                 \
        EBPF_PROTOCOL_FIXED_REQUEST_NO_REPLY, (void*)_ebpf_core_protocol_##OPERATION, \
            sizeof(ebpf_operation_##OPERATION##_request_t), .flags.value = FLAGS      \
    }

#define DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY(OPERATION, FLAGS)                              \
    {                                                                                                     \
        EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY, (void*)_ebpf_core_protocol_##OPERATION,                  \
            sizeof(ebpf_operation_##OPERATION##_request_t), sizeof(ebpf_operation_##OPERATION##_reply_t), \
            .flags.value = FLAGS                                                                          \
    }

#define DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_VARIABLE_REPLY(OPERATION, VARIABLE_REPLY, FLAGS)        \
    {                                                                                                  \
        EBPF_PROTOCOL_FIXED_REQUEST_VARIABLE_REPLY, (void*)_ebpf_core_protocol_##OPERATION,            \
            sizeof(ebpf_operation_##OPERATION##_request_t),                                            \
            EBPF_OFFSET_OF(ebpf_operation_##OPERATION##_reply_t, VARIABLE_REPLY), .flags.value = FLAGS \
    }

#define DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_NO_REPLY(OPERATION, VARIABLE_REQUEST, FLAGS)             \
    {                                                                                                      \
        EBPF_PROTOCOL_VARIABLE_REQUEST_NO_REPLY, (void*)_ebpf_core_protocol_##OPERATION,                   \
            EBPF_OFFSET_OF(ebpf_operation_##OPERATION##_request_t, VARIABLE_REQUEST), .flags.value = FLAGS \
    }

#define DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_FIXED_REPLY(OPERATION, VARIABLE_REQUEST, FLAGS) \
    {                                                                                             \
        EBPF_PROTOCOL_VARIABLE_REQUEST_FIXED_REPLY, (void*)_ebpf_core_protocol_##OPERATION,       \
            EBPF_OFFSET_OF(ebpf_operation_##OPERATION##_request_t, VARIABLE_REQUEST),             \
            sizeof(ebpf_operation_##OPERATION##_reply_t), .flags.value = FLAGS                    \
    }

#define DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_VARIABLE_REPLY(OPERATION, VARIABLE_REQUEST, VARIABLE_REPLY, FLAGS) \
    {                                                                                                                \
        EBPF_PROTOCOL_VARIABLE_REQUEST_VARIABLE_REPLY, (void*)_ebpf_core_protocol_##OPERATION,                       \
            EBPF_OFFSET_OF(ebpf_operation_##OPERATION##_request_t, VARIABLE_REQUEST),                                \
            EBPF_OFFSET_OF(ebpf_operation_##OPERATION##_reply_t, VARIABLE_REPLY), .flags.value = FLAGS               \
    }

#define DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY_ASYNC(OPERATION, FLAGS)                        \
    {                                                                                                     \
        EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY_ASYNC, (void*)_ebpf_core_protocol_##OPERATION,            \
            sizeof(ebpf_operation_##OPERATION##_request_t), sizeof(ebpf_operation_##OPERATION##_reply_t), \
            .flags.value = FLAGS                                                                          \
    }

#define DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_VARIABLE_REPLY_ASYNC(                                \
    OPERATION, VARIABLE_REQUEST, VARIABLE_REPLY, FLAGS)                                                \
    {                                                                                                  \
        EBPF_PROTOCOL_VARIABLE_REQUEST_VARIABLE_REPLY_ASYNC, (void*)_ebpf_core_protocol_##OPERATION,   \
            EBPF_OFFSET_OF(ebpf_operation_##OPERATION##_request_t, VARIABLE_REQUEST),                  \
            EBPF_OFFSET_OF(ebpf_operation_##OPERATION##_reply_t, VARIABLE_REPLY), .flags.value = FLAGS \
    }

#define ALIAS_TYPES(X, Y)                                                  \
    typedef ebpf_operation_##X##_request_t ebpf_operation_##Y##_request_t; \
    typedef ebpf_operation_##X##_reply_t ebpf_operation_##Y##_reply_t;

ALIAS_TYPES(get_next_id, get_next_link_id)
ALIAS_TYPES(get_next_id, get_next_map_id)
ALIAS_TYPES(get_next_id, get_next_program_id)
ALIAS_TYPES(get_handle_by_id, get_link_handle_by_id)
ALIAS_TYPES(get_handle_by_id, get_map_handle_by_id)
ALIAS_TYPES(get_handle_by_id, get_program_handle_by_id)

static ebpf_protocol_handler_t _ebpf_protocol_handlers[] = {

    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_VARIABLE_REPLY(resolve_helper, helper_id, address, PROTOCOL_JIT_MODE),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_VARIABLE_REPLY(resolve_map, map_handle, address, PROTOCOL_JIT_MODE),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_FIXED_REPLY(create_program, data, PROTOCOL_JIT_OR_INTERPRET_MODE),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_FIXED_REPLY(create_map, data, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_NO_REPLY(load_code, code, PROTOCOL_JIT_OR_INTERPRET_MODE),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_VARIABLE_REPLY(map_find_element, key, value, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_NO_REPLY(map_update_element, data, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_NO_REPLY(map_update_element_with_handle, key, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_NO_REPLY(map_delete_element, key, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_VARIABLE_REPLY(
        map_get_next_key, previous_key, next_key, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_VARIABLE_REPLY(query_program_info, data, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_NO_REPLY(update_pinning, path, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_FIXED_REPLY(get_pinned_object, path, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_FIXED_REPLY(link_program, data, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_NO_REPLY(unlink_program, data, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_NO_REPLY(close_handle, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY(get_ec_function, PROTOCOL_JIT_MODE),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_VARIABLE_REPLY(get_program_info, data, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_VARIABLE_REPLY(get_pinned_map_info, data, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY(get_link_handle_by_id, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY(get_map_handle_by_id, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY(get_program_handle_by_id, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY(get_next_link_id, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY(get_next_map_id, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY(get_next_program_id, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_VARIABLE_REPLY(get_object_info, info, info, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_VARIABLE_REPLY(
        get_next_pinned_program_path, start_path, next_path, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_NO_REPLY(bind_map, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY(ring_buffer_map_query_buffer, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_FIXED_REPLY_ASYNC(ring_buffer_map_async_query, PROTOCOL_ALL_MODES),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_FIXED_REPLY(load_native_module, data, PROTOCOL_NATIVE_MODE),
    DECLARE_PROTOCOL_HANDLER_FIXED_REQUEST_VARIABLE_REPLY(load_native_programs, data, PROTOCOL_NATIVE_MODE),
    DECLARE_PROTOCOL_HANDLER_VARIABLE_REQUEST_VARIABLE_REPLY_ASYNC(program_test_run, data, data, PROTOCOL_ALL_MODES),
};

_Must_inspect_result_ ebpf_result_t
ebpf_core_get_protocol_handler_properties(
    ebpf_operation_id_t operation_id,
    _Out_ size_t* minimum_request_size,
    _Out_ size_t* minimum_reply_size,
    _Out_ bool* async)
{
    // Native is always permitted.
    bool native_permitted = true;

#if defined(CONFIG_BPF_JIT_DISABLED)
    bool jit_permitted = false;
#else
    // JIT is permitted only if HVCI is off.
    bool jit_permitted = (_ebpf_core_code_integrity_state == EBPF_CODE_INTEGRITY_DEFAULT) ? true : false;
#endif

    // Interpret is only permitted if CONFIG_BPF_INTERPRETER_DISABLED is not set.
#if defined(CONFIG_BPF_INTERPRETER_DISABLED)
    bool interpret_permitted = false;
#else
    bool interpret_permitted = true;
#endif

    *minimum_request_size = 0;
    *minimum_reply_size = 0;

    if (operation_id >= EBPF_COUNT_OF(_ebpf_protocol_handlers) || operation_id < EBPF_OPERATION_RESOLVE_HELPER) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    // Only permit this operation if one of the modes it is used for is permitted.
    if (
        // If it's used by native and native is permitted, allow it.
        (!_ebpf_protocol_handlers[operation_id].flags.bits.used_by_native || !native_permitted) &&
        // If it's used by JIT and JIT is permitted, allow it.
        (!_ebpf_protocol_handlers[operation_id].flags.bits.used_by_jit || !jit_permitted) &&
        // If it's used by interpreter and interpreter is permitted, allow it.
        (!_ebpf_protocol_handlers[operation_id].flags.bits.used_by_interpret || !interpret_permitted)) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_CORE,
            "Operation id %d not permitted due to system configuration",
            operation_id);
        return EBPF_BLOCKED_BY_POLICY;
    }

    if (!_ebpf_protocol_handlers[operation_id].dispatch.protocol_handler_no_reply) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    *minimum_request_size = _ebpf_protocol_handlers[operation_id].minimum_request_size;
    *minimum_reply_size = _ebpf_protocol_handlers[operation_id].minimum_reply_size;

    switch (_ebpf_protocol_handlers[operation_id].call_type) {
    case EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY_ASYNC:
    case EBPF_PROTOCOL_VARIABLE_REQUEST_VARIABLE_REPLY_ASYNC:
        *async = true;
        break;
    default:
        *async = false;
        break;
    }

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_core_invoke_protocol_handler(
    ebpf_operation_id_t operation_id,
    _In_reads_bytes_(input_buffer_length) const void* input_buffer,
    uint16_t input_buffer_length,
    _Out_writes_bytes_opt_(output_buffer_length) void* output_buffer,
    uint16_t output_buffer_length,
    _Inout_opt_ void* async_context,
    _In_opt_ void (*on_complete)(_Inout_ void*, size_t, ebpf_result_t))
{
    ebpf_result_t retval;
    ebpf_epoch_state_t* epoch_state = NULL;
    ebpf_protocol_handler_t* handler = &_ebpf_protocol_handlers[operation_id];
    ebpf_operation_header_t* request = (ebpf_operation_header_t*)input_buffer;
    ebpf_operation_header_t* reply = (ebpf_operation_header_t*)output_buffer;

    if (operation_id >= EBPF_COUNT_OF(_ebpf_protocol_handlers) || operation_id < EBPF_OPERATION_RESOLVE_HELPER) {
        retval = EBPF_OPERATION_NOT_SUPPORTED;
        goto Done;
    }

    if (input_buffer_length > UINT16_MAX) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (output_buffer_length > UINT16_MAX) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (!input_buffer || !input_buffer_length) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Validate input_buffer_length.
    switch (handler->call_type) {
    case EBPF_PROTOCOL_FIXED_REQUEST_NO_REPLY:
    case EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY:
    case EBPF_PROTOCOL_FIXED_REQUEST_VARIABLE_REPLY:
    case EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY_ASYNC:
        if (input_buffer_length != handler->minimum_request_size) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        break;
    case EBPF_PROTOCOL_VARIABLE_REQUEST_NO_REPLY:
    case EBPF_PROTOCOL_VARIABLE_REQUEST_FIXED_REPLY:
    case EBPF_PROTOCOL_VARIABLE_REQUEST_VARIABLE_REPLY:
        if (input_buffer_length < handler->minimum_request_size) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        break;
    }

    // Validate output_buffer_length and output_buffer.
    switch (handler->call_type) {
    case EBPF_PROTOCOL_FIXED_REQUEST_NO_REPLY:
    case EBPF_PROTOCOL_VARIABLE_REQUEST_NO_REPLY:
        if (output_buffer || output_buffer_length) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        break;
    case EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY:
    case EBPF_PROTOCOL_VARIABLE_REQUEST_FIXED_REPLY:
    case EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY_ASYNC:
        if (!output_buffer || output_buffer_length != handler->minimum_reply_size) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        break;
    case EBPF_PROTOCOL_FIXED_REQUEST_VARIABLE_REPLY:
    case EBPF_PROTOCOL_VARIABLE_REQUEST_VARIABLE_REPLY:
        if (!output_buffer || output_buffer_length < handler->minimum_reply_size) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        break;
    }

    if (request->length > input_buffer_length || request->length < sizeof(*request)) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    epoch_state = ebpf_epoch_enter();
    retval = EBPF_SUCCESS;

    switch (handler->call_type) {
    case EBPF_PROTOCOL_FIXED_REQUEST_NO_REPLY:
    case EBPF_PROTOCOL_VARIABLE_REQUEST_NO_REPLY:
        retval = handler->dispatch.protocol_handler_no_reply(request);
        break;

    case EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY:
    case EBPF_PROTOCOL_VARIABLE_REQUEST_FIXED_REPLY:
        // Validated above.
        _Analysis_assume_(reply);
        retval = handler->dispatch.protocol_handler_with_fixed_reply(request, reply);
        reply->id = operation_id;
        reply->length = (uint16_t)handler->minimum_reply_size;
        break;

    case EBPF_PROTOCOL_FIXED_REQUEST_FIXED_REPLY_ASYNC:
        // Validated above.
        _Analysis_assume_(reply);
        if (!async_context || !on_complete) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        retval = ebpf_async_set_completion_callback(async_context, on_complete);
        if (retval != EBPF_SUCCESS) {
            goto Done;
        }
        retval =
            handler->dispatch.async_protocol_handler_with_reply(request, reply, output_buffer_length, async_context);
        if ((retval != EBPF_SUCCESS) && (retval != EBPF_PENDING)) {
            ebpf_assert_success(ebpf_async_reset_completion_callback(async_context));
        }
        break;

    case EBPF_PROTOCOL_FIXED_REQUEST_VARIABLE_REPLY:
    case EBPF_PROTOCOL_VARIABLE_REQUEST_VARIABLE_REPLY:
        // Validated above.
        _Analysis_assume_(reply);
        retval = handler->dispatch.protocol_handler_with_variable_reply(request, reply, output_buffer_length);
        reply->id = operation_id;
        break;
    case EBPF_PROTOCOL_VARIABLE_REQUEST_VARIABLE_REPLY_ASYNC:
        // Validated above.
        _Analysis_assume_(reply);
        if (!async_context || !on_complete) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        retval = ebpf_async_set_completion_callback(async_context, on_complete);
        if (retval != EBPF_SUCCESS) {
            goto Done;
        }
        retval =
            handler->dispatch.async_protocol_handler_with_reply(request, reply, output_buffer_length, async_context);
        if ((retval != EBPF_SUCCESS) && (retval != EBPF_PENDING)) {
            ebpf_assert_success(ebpf_async_reset_completion_callback(async_context));
        }
        break;
    }

Done:
    if (epoch_state) {
        ebpf_epoch_exit(epoch_state);
    }
    return retval;
}

bool
ebpf_core_cancel_protocol_handler(_Inout_ void* async_context)
{
    ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
    bool return_value = ebpf_async_cancel(async_context);
    ebpf_epoch_exit(epoch_state);
    return return_value;
}

void
ebpf_core_close_context(_In_opt_ void* context)
{
    if (!context) {
        return;
    }

    ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();

    ebpf_core_object_t* object = (ebpf_core_object_t*)context;
    object->base.release_reference(object);

    ebpf_epoch_exit(epoch_state);
}
