/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "pch.h"
#include "ebpf_protocol.h"

#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_platform.h"
#include "ubpf.h"

#define RTL_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define RTL_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))

#if defined(NTDDI_VERSION)
#define false FALSE
#define true TRUE

#else
#define UNREFERENCED_PARAMETER(X) (X)
#endif

typedef struct _ebpf_core_code_entry
{
    // pointer to code buffer
    ebpf_code_type_t code_type;

    uint8_t* file_name;
    size_t file_name_length;
    uint8_t* section_name;
    size_t section_name_length;

    // determinant is code_type
    union
    {
        // EBPF_CODE_NATIVE
        uint8_t* code;

        // EBPF_CODE_EBPF
        struct ubpf_vm* vm;
    } code_or_vm;
    ebpf_program_type_t hook_point;
} ebpf_core_code_entry_t;

typedef struct _ebpf_core_pinning_entry
{
    uint64_t handle;
    size_t name_length;
    uint8_t name[1];
} ebpf_core_pinning_entry_t;

static ebpf_lock_t _ebpf_core_code_entry_table_lock = {0};
static ebpf_core_code_entry_t* _ebpf_core_code_entry_table[1024] = {0};

static ebpf_lock_t _ebpf_core_map_entry_table_lock = {0};
static ebpf_core_map_t* _ebpf_core_map_entry_table[1024] = {0};

static ebpf_lock_t _ebpf_core_hook_table_lock = {0};
static ebpf_core_code_entry_t* _ebpf_core_hook_table[EBPF_PROGRAM_TYPE_BIND + 1] = {0};

static ebpf_lock_t _ebpf_core_pinning_table_lock = {0};
static ebpf_core_pinning_entry_t* _ebpf_core_pinning_table[1024] = {0};

// Assume enabled until we can query it
static ebpf_code_integrity_state_t _ebpf_core_code_integrity_state = EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE;

static void*
_ebpf_core_map_lookup_element(ebpf_core_map_t* map, const uint8_t* key);
static void
_ebpf_core_map_update_element(ebpf_core_map_t* map, const uint8_t* key, const uint8_t* data);
static void
_ebpf_core_map_delete_element(ebpf_core_map_t* map, const uint8_t* key);

static uint64_t
ebpf_core_interpreter_helper_resolver(void* context, uint32_t helper_id);

static const void* _ebpf_program_helpers[] = {
    NULL,
    (void*)&_ebpf_core_map_lookup_element,
    (void*)&_ebpf_core_map_update_element,
    (void*)&_ebpf_core_map_delete_element};

static uint64_t
_ebpf_core_insert_map_entry(ebpf_core_map_t* map)
{
    uint64_t handle = UINT64_MAX;
    uint64_t index = 0;
    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_map_entry_table_lock, &state);
    for (index = 1; index < RTL_COUNT_OF(_ebpf_core_map_entry_table); index++) {
        if (!_ebpf_core_map_entry_table[index]) {
            handle = index;
            _ebpf_core_map_entry_table[index] = map;
            break;
        }
    }
    ebpf_lock_unlock(&_ebpf_core_map_entry_table_lock, &state);
    return handle;
}

static uint64_t
_ebpf_core_insert_code_entry(ebpf_core_code_entry_t* code)
{
    uint64_t handle = UINT64_MAX;
    uint64_t index = 0;
    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_code_entry_table_lock, &state);
    for (index = 1; index < RTL_COUNT_OF(_ebpf_core_code_entry_table); index++) {
        if (!_ebpf_core_code_entry_table[index]) {
            handle = index;
            _ebpf_core_code_entry_table[index] = code;
            break;
        }
    }
    ebpf_lock_unlock(&_ebpf_core_code_entry_table_lock, &state);
    return handle;
}

static ebpf_error_code_t
_ebpf_core_set_hook_entry(ebpf_core_code_entry_t* code, ebpf_program_type_t program_type)
{
    ebpf_lock_state_t state;
    if (program_type > EBPF_PROGRAM_TYPE_BIND || program_type <= EBPF_PROGRAM_TYPE_UNSPECIFIED) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }
    ebpf_lock_lock(&_ebpf_core_hook_table_lock, &state);
    _ebpf_core_hook_table[program_type] = code;
    ebpf_lock_unlock(&_ebpf_core_hook_table_lock, &state);
    return EBPF_ERROR_SUCCESS;
}

static ebpf_core_code_entry_t*
_ebpf_core_get_hook_entry(ebpf_program_type_t program_type)
{
    ebpf_core_code_entry_t* code = NULL;
    ebpf_lock_state_t state;
    if (program_type > EBPF_PROGRAM_TYPE_BIND || program_type <= EBPF_PROGRAM_TYPE_UNSPECIFIED) {
        return NULL;
    }
    ebpf_lock_lock(&_ebpf_core_hook_table_lock, &state);
    code = _ebpf_core_hook_table[program_type];
    ebpf_lock_unlock(&_ebpf_core_hook_table_lock, &state);
    return code;
}

static ebpf_core_map_t*
_ebpf_core_find_map_entry(uint64_t handle)
{
    ebpf_core_map_t* map;
    if (handle > RTL_COUNT_OF(_ebpf_core_map_entry_table)) {
        return NULL;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_map_entry_table_lock, &state);
    map = _ebpf_core_map_entry_table[handle];
    ebpf_lock_unlock(&_ebpf_core_map_entry_table_lock, &state);
    return map;
}

// Helper functions for pinning entry table
static uint64_t
_ebpf_core_insert_pinning_entry(ebpf_core_pinning_entry_t* pin)
{
    uint64_t handle = UINT64_MAX;
    uint64_t index = 0;
    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_pinning_table_lock, &state);
    for (index = 1; index < RTL_COUNT_OF(_ebpf_core_pinning_table); index++) {
        if (!_ebpf_core_pinning_table[index]) {
            handle = index;
            _ebpf_core_pinning_table[index] = pin;
            break;
        }
    }
    ebpf_lock_unlock(&_ebpf_core_pinning_table_lock, &state);
    return handle;
}

static void
_ebpf_core_delete_pinning_entry(const uint8_t* name, const size_t name_length)
{
    uint64_t index = 0;
    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_pinning_table_lock, &state);
    for (index = 1; index < RTL_COUNT_OF(_ebpf_core_pinning_table); index++) {
        if (_ebpf_core_pinning_table[index] && name_length == _ebpf_core_pinning_table[index]->name_length &&
            memcmp(name, _ebpf_core_pinning_table[index]->name, name_length) == 0) {
            ebpf_free(_ebpf_core_pinning_table[index]);
            _ebpf_core_pinning_table[index] = NULL;
        }
    }
    ebpf_lock_unlock(&_ebpf_core_pinning_table_lock, &state);
}

static uint64_t
_ebpf_core_find_pinning_entry(const uint8_t* name, const size_t name_length)
{
    uint64_t handle = UINT64_MAX;
    uint64_t index = 0;
    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_pinning_table_lock, &state);
    for (index = 1; index < RTL_COUNT_OF(_ebpf_core_pinning_table); index++) {
        if (_ebpf_core_pinning_table[index] && name_length == _ebpf_core_pinning_table[index]->name_length &&
            memcmp(name, _ebpf_core_pinning_table[index]->name, name_length) == 0) {
            handle = index;
            break;
        }
    }
    ebpf_lock_unlock(&_ebpf_core_pinning_table_lock, &state);
    return handle;
}

static ebpf_core_code_entry_t*
_ebpf_core_find_code_entry(uint64_t handle)
{
    ebpf_core_code_entry_t* code;
    if (handle > RTL_COUNT_OF(_ebpf_core_code_entry_table)) {
        return NULL;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_code_entry_table_lock, &state);
    code = _ebpf_core_code_entry_table[handle];
    ebpf_lock_unlock(&_ebpf_core_code_entry_table_lock, &state);
    return code;
}

static ebpf_error_code_t
_ebpf_core_delete_map_entry(uint64_t handle)
{
    ebpf_core_map_t* map;
    if (handle > RTL_COUNT_OF(_ebpf_core_map_entry_table)) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_map_entry_table_lock, &state);
    map = _ebpf_core_map_entry_table[handle];
    if (map) {
        ebpf_map_function_tables[map->ebpf_map_definition.type].delete_map(map);
        _ebpf_core_map_entry_table[handle] = NULL;
    }
    ebpf_lock_unlock(&_ebpf_core_map_entry_table_lock, &state);
    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t
_ebpf_core_delete_code_entry(uint64_t handle)
{
    ebpf_error_code_t retval = EBPF_ERROR_NOT_FOUND;
    ebpf_core_code_entry_t* code;
    if (handle > RTL_COUNT_OF(_ebpf_core_code_entry_table)) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_code_entry_table_lock, &state);
    code = _ebpf_core_code_entry_table[handle];
    if (code) {
        if (code && code->code_type == EBPF_CODE_EBPF) {
            ubpf_destroy(code->code_or_vm.vm);
        }

        ebpf_free(code);
        _ebpf_core_code_entry_table[handle] = NULL;
        retval = EBPF_ERROR_SUCCESS;
    } else {
        retval = EBPF_ERROR_INVALID_HANDLE;
    }
    ebpf_lock_unlock(&_ebpf_core_code_entry_table_lock, &state);
    return retval;
}

ebpf_error_code_t
ebpf_core_initialize()
{
    ebpf_lock_create(&_ebpf_core_code_entry_table_lock);
    ebpf_lock_create(&_ebpf_core_map_entry_table_lock);
    ebpf_lock_create(&_ebpf_core_hook_table_lock);
    ebpf_lock_create(&_ebpf_core_pinning_table_lock);

    return ebpf_query_code_integrity_state(&_ebpf_core_code_integrity_state);
}

void
ebpf_core_terminate()
{
    size_t index;
    for (index = 0; index < RTL_COUNT_OF(_ebpf_core_map_entry_table); index++) {
        _ebpf_core_delete_map_entry(index);
    }
    for (index = 0; index < RTL_COUNT_OF(_ebpf_core_map_entry_table); index++) {
        _ebpf_core_delete_code_entry(index);
    }

    for (index = 0; index < RTL_COUNT_OF(_ebpf_core_pinning_table); index++) {
        _ebpf_core_delete_code_entry(index);
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_pinning_table_lock, &state);
    for (index = 0; index < RTL_COUNT_OF(_ebpf_core_pinning_table); index++)
        ebpf_free(_ebpf_core_pinning_table[index]);
    ebpf_lock_unlock(&_ebpf_core_pinning_table_lock, &state);
}

static ebpf_error_code_t
ebpf_core_protocol_attach_code(_In_ const struct _ebpf_operation_attach_detach_request* request)
{
    ebpf_error_code_t retval = EBPF_ERROR_NOT_FOUND;
    ebpf_core_code_entry_t* code = NULL;

    switch (request->hook) {
    case EBPF_PROGRAM_TYPE_XDP:
    case EBPF_PROGRAM_TYPE_BIND:
        break;
    default:
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    code = _ebpf_core_find_code_entry(request->handle);
    if (!code) {
        retval = EBPF_ERROR_INVALID_HANDLE;
        goto Done;
    }

    code->hook_point = request->hook;
    _ebpf_core_set_hook_entry(code, code->hook_point);
    retval = EBPF_ERROR_SUCCESS;

Done:
    return retval;
}

static ebpf_error_code_t
ebpf_core_protocol_detach_code(_In_ const struct _ebpf_operation_attach_detach_request* request)
{
    ebpf_error_code_t retval = EBPF_ERROR_NOT_FOUND;
    ebpf_core_code_entry_t* code = NULL;

    code = _ebpf_core_find_code_entry(request->handle);
    if (!code) {
        retval = EBPF_ERROR_INVALID_HANDLE;
        goto Done;
    }

    _ebpf_core_set_hook_entry(NULL, code->hook_point);
    code->hook_point = EBPF_PROGRAM_TYPE_UNSPECIFIED;
    retval = EBPF_ERROR_SUCCESS;

Done:
    return retval;
}

static ebpf_error_code_t
ebpf_core_protocol_unload_code(_In_ const struct _ebpf_operation_unload_code_request* request)
{
    return _ebpf_core_delete_code_entry(request->handle);
}

static ebpf_error_code_t
ebpf_core_protocol_load_code(
    _In_ const ebpf_operation_load_code_request_t* request,
    _Inout_ struct _ebpf_operation_load_code_reply* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    size_t blob_size = request->header.length - RTL_OFFSET_OF(ebpf_operation_load_code_request_t, data);
    size_t allocation_size = 0;
    ebpf_core_code_entry_t* code_entry = NULL;
    ebpf_memory_type_t memory_type;
    uint8_t* file_name = NULL;
    size_t file_name_length = 0;
    uint8_t* section_name = NULL;
    size_t section_name_length = 0;
    uint8_t* code = NULL;
    size_t code_length = 0;

    UNREFERENCED_PARAMETER(reply_length);

    retval = ebpf_safe_size_t_add(blob_size, sizeof(ebpf_core_code_entry_t), &allocation_size);
    if (retval != EBPF_ERROR_SUCCESS) {
        goto Done;
    }

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
        memory_type = EBPF_MEMORY_EXECUTE;
    } else {
        memory_type = EBPF_MEMORY_NO_EXECUTE;
    }

    code_entry = ebpf_allocate(allocation_size, memory_type);
    if (!code_entry) {
        retval = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }

    file_name = (uint8_t*)request + request->file_name_offset;
    section_name = (uint8_t*)request + request->section_name_offset;
    code = (uint8_t*)request + request->code_offset;
    file_name_length = section_name - file_name;
    section_name_length = code - section_name;
    code_length = request->header.length - request->code_offset;

    code_entry->file_name = (uint8_t*)(code_entry + 1);
    code_entry->file_name_length = file_name_length;
    memcpy(code_entry->file_name, file_name, code_entry->file_name_length);
    code_entry->section_name = code_entry->file_name + file_name_length;
    code_entry->section_name_length = section_name_length;
    memcpy(code_entry->section_name, section_name, code_entry->section_name_length);

    if (request->code_type == EBPF_CODE_NATIVE) {
        code_entry->code_type = EBPF_CODE_NATIVE;
        code_entry->code_or_vm.code = code_entry->section_name + section_name_length;
        memcpy(code_entry->code_or_vm.code, code, code_length);
    } else {
        char* error_message = NULL;
        code_entry->code_type = EBPF_CODE_EBPF;
        code_entry->code_or_vm.vm = ubpf_create();
        if (!code_entry->code_or_vm.vm) {
            retval = EBPF_ERROR_OUT_OF_RESOURCES;
            goto Done;
        }

        // BUG - ubpf implements bounds checking to detect interpreted code accesing
        // memory out of bounds. Currently this is flagging valid access checks and
        // failing.
        toggle_bounds_check(code_entry->code_or_vm.vm, false);

        ubpf_register_helper_resolver(code_entry->code_or_vm.vm, code_entry, ebpf_core_interpreter_helper_resolver);
        if (ubpf_load(code_entry->code_or_vm.vm, code, (uint32_t)code_length, &error_message) != 0) {
            ebpf_free(error_message);
            retval = EBPF_ERROR_INVALID_PARAMETER;
            goto Done;
        }
    }
    reply->handle = _ebpf_core_insert_code_entry(code_entry);

    retval = reply->handle != UINT64_MAX ? EBPF_ERROR_SUCCESS : EBPF_ERROR_OUT_OF_RESOURCES;

Done:
    if (retval != EBPF_ERROR_SUCCESS) {
        if (code_entry && code_entry->code_type == EBPF_CODE_EBPF) {
            ubpf_destroy(code_entry->code_or_vm.vm);
        }
        ebpf_free(code_entry);
    }
    return retval;
}

static ebpf_error_code_t
ebpf_core_protocol_resolve_helper(
    _In_ const struct _ebpf_operation_resolve_helper_request* request,
    _Inout_ struct _ebpf_operation_resolve_helper_reply* reply,
    uint16_t reply_length)
{
    UNREFERENCED_PARAMETER(reply_length);

    if (request->helper_id[0] >= RTL_COUNT_OF(_ebpf_program_helpers)) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }
    reply->address[0] = (uint64_t)_ebpf_program_helpers[request->helper_id[0]];

    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t
ebpf_core_protocol_resolve_map(
    _In_ const struct _ebpf_operation_resolve_map_request* request,
    _Inout_ struct _ebpf_operation_resolve_map_reply* reply,
    uint16_t reply_length)
{
    ebpf_core_map_t* map;
    UNREFERENCED_PARAMETER(reply_length);

    map = _ebpf_core_find_map_entry(request->map_handle[0]);
    if (map) {
        reply->address[0] = (uint64_t)map;
        return EBPF_ERROR_SUCCESS;
    } else {
        return EBPF_ERROR_INVALID_HANDLE;
    }
}

ebpf_error_code_t
ebpf_core_invoke_hook(_In_ ebpf_program_type_t hook_point, _Inout_ void* context, _Inout_ uint32_t* result)
{
    ebpf_core_code_entry_t* code = NULL;
    ebpf_hook_function function_pointer;
    char* error_message = NULL;

    code = _ebpf_core_get_hook_entry(hook_point);
    if (code) {
        if (code->code_type == EBPF_CODE_NATIVE) {
            function_pointer = (ebpf_hook_function)(code->code_or_vm.code);
            *result = (function_pointer)(context);
            return EBPF_ERROR_SUCCESS;
        } else {
            *result = (uint32_t)(ubpf_exec(code->code_or_vm.vm, context, 1024, &error_message));
            if (error_message) {
                ebpf_free(error_message);
            }
            return EBPF_ERROR_SUCCESS;
        }
    }
    // Nothing to do if no hook is registered.
    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t
ebpf_core_protocol_create_map(
    _In_ const struct _ebpf_operation_create_map_request* request,
    _Inout_ struct _ebpf_operation_create_map_reply* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    ebpf_core_map_t* map = NULL;
    size_t type = request->ebpf_map_definition.type;

    UNREFERENCED_PARAMETER(reply_length);
    if (type >= RTL_COUNT_OF(ebpf_map_function_tables)) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    if (ebpf_map_function_tables[type].create_map == NULL) {
        retval = EBPF_ERROR_NOT_SUPPORTED;
        goto Done;
    }

    map = ebpf_map_function_tables[type].create_map(&request->ebpf_map_definition);
    if (map == NULL) {
        retval = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }

    reply->handle = _ebpf_core_insert_map_entry(map);
    if (reply->handle == UINT64_MAX) {
        retval = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }
    map = NULL;

    retval = EBPF_ERROR_SUCCESS;

Done:
    if (map != NULL) {
        ebpf_map_function_tables[type].delete_map(map);
    }

    return retval;
}

static ebpf_error_code_t
ebpf_core_protocol_map_lookup_element(
    _In_ const ebpf_operation_map_lookup_element_request_t* request,
    _Inout_ ebpf_operation_map_lookup_element_reply_t* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    ebpf_core_map_t* map = NULL;
    size_t type;
    uint8_t* value = NULL;

    map = _ebpf_core_find_map_entry(request->handle);
    if (!map) {
        retval = EBPF_ERROR_INVALID_HANDLE;
        goto Done;
    }

    type = map->ebpf_map_definition.type;

    if (request->header.length <
        (RTL_OFFSET_OF(ebpf_operation_map_lookup_element_request_t, key) + map->ebpf_map_definition.key_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    if (reply_length <
        (RTL_OFFSET_OF(ebpf_operation_map_lookup_element_reply_t, value) + map->ebpf_map_definition.value_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    value = ebpf_map_function_tables[type].lookup_entry(map, request->key);
    if (value == NULL) {
        retval = EBPF_ERROR_NOT_FOUND;
        goto Done;
    }

    memcpy(reply->value, value, map->ebpf_map_definition.value_size);
    retval = EBPF_ERROR_SUCCESS;

Done:
    return retval;
}

static ebpf_error_code_t
ebpf_core_protocol_map_update_element(_In_ const epf_operation_map_update_element_request_t* request)
{
    ebpf_error_code_t retval;
    ebpf_core_map_t* map = NULL;
    size_t type;

    map = _ebpf_core_find_map_entry(request->handle);
    if (!map) {
        retval = EBPF_ERROR_INVALID_HANDLE;
        goto Done;
    }

    type = map->ebpf_map_definition.type;

    if (request->header.length < (RTL_OFFSET_OF(epf_operation_map_update_element_request_t, data) +
                                  map->ebpf_map_definition.key_size + map->ebpf_map_definition.value_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    retval = ebpf_map_function_tables[type].update_entry(
        map, request->data, request->data + map->ebpf_map_definition.key_size);

Done:
    return retval;
}

static ebpf_error_code_t
ebpf_core_protocol_map_delete_element(_In_ const ebpf_operation_map_delete_element_request_t* request)
{
    ebpf_error_code_t retval;
    ebpf_core_map_t* map = NULL;
    size_t type;

    map = _ebpf_core_find_map_entry(request->handle);
    if (!map) {
        retval = EBPF_ERROR_INVALID_HANDLE;
        goto Done;
    }

    type = map->ebpf_map_definition.type;

    if (request->header.length <
        (RTL_OFFSET_OF(ebpf_operation_map_delete_element_request_t, key) + map->ebpf_map_definition.key_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    retval = ebpf_map_function_tables[type].delete_entry(map, request->key);

Done:
    return retval;
}

static ebpf_error_code_t
ebpf_core_protocol_map_get_next_key(
    _In_ const ebpf_operation_map_get_next_key_request_t* request,
    _Inout_ ebpf_operation_map_get_next_key_reply_t* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    ebpf_core_map_t* map = NULL;
    size_t type;
    const uint8_t* previous_key;
    uint8_t* next_key = NULL;

    map = _ebpf_core_find_map_entry(request->handle);
    if (!map) {
        retval = EBPF_ERROR_INVALID_HANDLE;
        goto Done;
    }

    type = map->ebpf_map_definition.type;
    if (ebpf_map_function_tables[type].next_key == NULL) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    // If request length shows zero key, treat as restart.
    if (request->header.length == RTL_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key)) {
        previous_key = NULL;
    } else if (
        request->header.length <
        (RTL_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key) + map->ebpf_map_definition.key_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    } else {
        previous_key = request->previous_key;
    }

    next_key = reply->next_key;
    if (reply_length <
        (RTL_OFFSET_OF(ebpf_operation_map_get_next_key_reply_t, next_key) + map->ebpf_map_definition.key_size)) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    retval = ebpf_map_function_tables[type].next_key(map, previous_key, next_key);

Done:
    return retval;
}

static ebpf_error_code_t
ebpf_core_protocol_get_next_map(
    _In_ const struct _ebpf_operation_get_next_map_request* request,
    _Inout_ struct _ebpf_operation_get_next_map_reply* reply,
    uint16_t reply_length)
{
    uint64_t next_handle = request->previous_handle;
    UNREFERENCED_PARAMETER(reply_length);

    // Start search from begining
    if (next_handle == UINT64_MAX) {
        next_handle = 1;
    } else {
        next_handle++;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_map_entry_table_lock, &state);
    for (; next_handle < RTL_COUNT_OF(_ebpf_core_map_entry_table); next_handle++) {
        if (_ebpf_core_map_entry_table[next_handle] != NULL) {
            break;
        }
    }
    ebpf_lock_unlock(&_ebpf_core_map_entry_table_lock, &state);

    // No more handles, return end
    if (next_handle == RTL_COUNT_OF(_ebpf_core_map_entry_table)) {
        next_handle = UINT64_MAX;
    }

    reply->next_handle = next_handle;
    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t
ebpf_core_protocol_get_next_program(
    _In_ const struct _ebpf_operation_get_next_program_request* request,
    _Inout_ struct _ebpf_operation_get_next_program_reply* reply,
    uint16_t reply_length)
{
    uint64_t next_handle = request->previous_handle;
    UNREFERENCED_PARAMETER(reply_length);

    // Start search from begining
    if (next_handle == UINT64_MAX) {
        next_handle = 1;
    } else {
        next_handle++;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_code_entry_table_lock, &state);
    for (; next_handle < RTL_COUNT_OF(_ebpf_core_code_entry_table); next_handle++) {
        if (_ebpf_core_code_entry_table[next_handle] != NULL) {
            break;
        }
    }
    ebpf_lock_unlock(&_ebpf_core_code_entry_table_lock, &state);

    // No more handles, return end
    if (next_handle == RTL_COUNT_OF(_ebpf_core_code_entry_table)) {
        next_handle = UINT64_MAX;
    }

    reply->next_handle = next_handle;
    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t
ebpf_core_protocol_query_map_definition(
    _In_ const struct _ebpf_operation_query_map_definition_request* request,
    _Inout_ struct _ebpf_operation_query_map_definition_reply* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval = EBPF_ERROR_INVALID_HANDLE;
    ebpf_core_map_t* map = NULL;
    UNREFERENCED_PARAMETER(reply_length);

    map = _ebpf_core_find_map_entry(request->handle);
    if (map) {
        reply->map_definition = map->ebpf_map_definition;
        retval = EBPF_ERROR_SUCCESS;
    }

    return retval;
}

static ebpf_error_code_t
ebpf_core_protocol_query_program_information(
    _In_ const struct _ebpf_operation_query_program_information_request* request,
    _Inout_ struct _ebpf_operation_query_program_information_reply* reply,
    uint16_t reply_length)
{
    ebpf_core_code_entry_t* code = NULL;
    size_t required_reply_length;

    code = _ebpf_core_find_code_entry(request->handle);
    if (!code) {
        return EBPF_ERROR_NOT_FOUND;
    }

    required_reply_length = RTL_OFFSET_OF(struct _ebpf_operation_query_program_information_reply, data) +
                            code->file_name_length + code->section_name_length;

    if (reply_length < required_reply_length) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    reply->file_name_offset = RTL_OFFSET_OF(struct _ebpf_operation_query_program_information_reply, data);
    reply->section_name_offset = reply->file_name_offset + (uint16_t)code->file_name_length;

    memcpy(reply->data, code->file_name, code->file_name_length);
    memcpy(reply->data + code->file_name_length, code->section_name, code->section_name_length);
    reply->code_type = code->code_type;

    reply->header.length = (uint16_t)required_reply_length;

    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t
ebpf_core_protocol_update_map_pinning(_In_ const struct _ebpf_operation_update_map_pinning_request* request)
{
    ebpf_error_code_t retval;
    ebpf_core_pinning_entry_t* entry = NULL;
    const uint8_t* name = request->name;
    size_t name_length = request->header.length - RTL_OFFSET_OF(ebpf_operation_update_map_pinning_request_t, name);

    if (name_length == 0) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    if (request->handle == UINT64_MAX) {
        _ebpf_core_delete_pinning_entry(request->name, name_length);
        retval = EBPF_ERROR_SUCCESS;
        goto Done;
    } else {
        size_t entry_size = RTL_OFFSET_OF(ebpf_core_pinning_entry_t, name) + name_length;

        entry = ebpf_allocate(entry_size, EBPF_MEMORY_NO_EXECUTE);
        if (!entry) {
            retval = EBPF_ERROR_OUT_OF_RESOURCES;
            goto Done;
        }
        entry->handle = request->handle;
        memcpy(entry->name, name, name_length);
        entry->name_length = name_length;

        if (_ebpf_core_insert_pinning_entry(entry) == UINT64_MAX) {
            retval = EBPF_ERROR_OUT_OF_RESOURCES;
            goto Done;
        }
        entry = NULL;
        retval = EBPF_ERROR_SUCCESS;
    }
Done:
    ebpf_free(entry);
    return retval;
}

static ebpf_error_code_t
ebpf_core_protocol_lookup_map_pinning(
    _In_ const struct _ebpf_operation_lookup_map_pinning_request* request,
    _Inout_ struct _ebpf_operation_lookup_map_pinning_reply* reply,
    uint16_t reply_length)
{
    ebpf_error_code_t retval;
    const uint8_t* name = request->name;
    size_t name_length = request->header.length - RTL_OFFSET_OF(ebpf_operation_lookup_map_pinning_request_t, name);
    UNREFERENCED_PARAMETER(reply_length);

    if (name_length == 0) {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    reply->handle = _ebpf_core_find_pinning_entry(name, name_length);
    if (reply->handle == UINT64_MAX) {
        retval = EBPF_ERROR_NOT_FOUND;
        goto Done;
    }

    retval = EBPF_ERROR_SUCCESS;

Done:
    return retval;
}

static void*
_ebpf_core_map_lookup_element(ebpf_core_map_t* map, const uint8_t* key)
{
    size_t type = map->ebpf_map_definition.type;
    return ebpf_map_function_tables[type].lookup_entry(map, key);
}

static void
_ebpf_core_map_update_element(ebpf_core_map_t* map, const uint8_t* key, const uint8_t* value)
{
    size_t type = map->ebpf_map_definition.type;
    ebpf_map_function_tables[type].update_entry(map, key, value);
}

static void
_ebpf_core_map_delete_element(ebpf_core_map_t* map, const uint8_t* key)
{
    size_t type = map->ebpf_map_definition.type;
    ebpf_map_function_tables[type].delete_entry(map, key);
}

static uint64_t
ebpf_core_interpreter_helper_resolver(void* context, uint32_t helper_id)
{
    UNREFERENCED_PARAMETER(context);
    if (helper_id >= RTL_COUNT_OF(_ebpf_program_helpers)) {
        return 0;
    }
    return (uint64_t)_ebpf_program_helpers[helper_id];
}

ebpf_protocol_handler_t EbpfProtocolHandlers[EBPF_OPERATION_LOOKUP_MAP_PINNING + 1] = {
    {NULL, sizeof(struct _ebpf_operation_eidence_request)}, // EBPF_OPERATION_EVIDENCE
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_resolve_helper,
     sizeof(struct _ebpf_operation_resolve_helper_request),
     sizeof(struct _ebpf_operation_resolve_helper_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_resolve_map,
     sizeof(struct _ebpf_operation_resolve_map_request),
     sizeof(struct _ebpf_operation_resolve_map_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_load_code,
     sizeof(struct _ebpf_operation_load_code_request),
     sizeof(struct _ebpf_operation_load_code_reply)},
    {ebpf_core_protocol_unload_code, sizeof(struct _ebpf_operation_unload_code_request), 0},
    {ebpf_core_protocol_attach_code, sizeof(struct _ebpf_operation_attach_detach_request), 0},
    {ebpf_core_protocol_detach_code, sizeof(struct _ebpf_operation_attach_detach_request), 0},
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_create_map,
     sizeof(struct _ebpf_operation_create_map_request),
     sizeof(struct _ebpf_operation_create_map_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_map_lookup_element,
     sizeof(struct _ebpf_operation_map_lookup_element_request),
     sizeof(struct _ebpf_operation_map_lookup_element_reply)},
    {ebpf_core_protocol_map_update_element, sizeof(struct _ebpf_operation_map_update_element_request), 0},
    {ebpf_core_protocol_map_delete_element, sizeof(struct _ebpf_operation_map_delete_element_request), 0},
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_map_get_next_key,
     RTL_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key),
     sizeof(ebpf_operation_map_get_next_key_reply_t)},
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_get_next_map,
     sizeof(struct _ebpf_operation_get_next_map_request),
     sizeof(struct _ebpf_operation_get_next_map_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_get_next_program,
     sizeof(struct _ebpf_operation_get_next_program_request),
     sizeof(struct _ebpf_operation_get_next_program_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_query_map_definition,
     sizeof(struct _ebpf_operation_query_map_definition_request),
     sizeof(struct _ebpf_operation_query_map_definition_reply)},
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_query_program_information,
     sizeof(struct _ebpf_operation_query_program_information_request),
     sizeof(struct _ebpf_operation_query_program_information_reply)},
    {ebpf_core_protocol_update_map_pinning, sizeof(struct _ebpf_operation_update_map_pinning_request), 0},
    {(ebpf_error_code_t(__cdecl*)(const void*))ebpf_core_protocol_lookup_map_pinning,
     sizeof(struct _ebpf_operation_lookup_map_pinning_request),
     sizeof(struct _ebpf_operation_lookup_map_pinning_reply)},
};