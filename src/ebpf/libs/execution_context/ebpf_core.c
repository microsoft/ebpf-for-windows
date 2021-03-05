/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include "pch.h"
#include "protocol.h"

#include "ebpf_core.h"
#include "ebpf_platform.h"
#include "ebpf_maps.h"
#include "ubpf.h"

#define RTL_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define RTL_OFFSET_OF(s, m) (((size_t)&((s*)0)->m))

typedef struct _ebpf_core_code_entry {
    // pointer to code buffer
    ebpf_code_type_t code_type;

    // determinant is code_type
    union {
        // EBPF_CODE_NATIVE
        uint8_t* code;

        // EBPF_CODE_EBPF
        struct ubpf_vm* vm;
    };
    ebpf_program_type_t hook_point;
} ebpf_core_code_entry_t;

static ebpf_lock_t _ebpf_core_code_entry_table_lock = { 0 };
static ebpf_core_code_entry_t* _ebpf_core_code_entry_table[1024] = { 0 };

static ebpf_lock_t _ebpf_core_map_entry_table_lock = { 0 };
static ebpf_core_map_t* _ebpf_core_map_entry_table[1024] = { 0 };

static ebpf_lock_t _ebpf_core_hook_table_lock = { 0 };
static ebpf_core_code_entry_t* _ebpf_core_hook_table[EBPF_PROGRAM_TYPE_BIND + 1] = { 0 };

static void* _ebpf_core_map_lookup_element(ebpf_core_map_t* map, const uint8_t* key);
static void _ebpf_core_map_update_element(ebpf_core_map_t* map, const uint8_t* key, const uint8_t* data);
static void _ebpf_core_map_delete_element(ebpf_core_map_t* map, const uint8_t* key);

static uint64_t ebpf_core_interpreter_helper_resolver(void* context, uint32_t helper_id);

static const void * _ebpf_program_helpers[] =
{
    NULL,
    (void*)&_ebpf_core_map_lookup_element,
    (void*)&_ebpf_core_map_update_element,
    (void*)&_ebpf_core_map_delete_element
};

static uint64_t _ebpf_core_insert_map_entry(ebpf_core_map_t* map)
{
    uint64_t handle = INT64_MAX;
    uint64_t index = 0;
    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_map_entry_table_lock, &state);
    for (index = 1; index < RTL_COUNT_OF(_ebpf_core_map_entry_table); index++)
    {
        if (!_ebpf_core_map_entry_table[index])
        {
            handle = index;
            _ebpf_core_map_entry_table[index] = map;
            break;
        }
    }
    ebpf_lock_unlock(&_ebpf_core_map_entry_table_lock, &state);
    return handle;
}

static uint64_t _ebpf_core_insert_code_entry(ebpf_core_code_entry_t* code)
{
    uint64_t handle = INT64_MAX;
    uint64_t index = 0;
    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_code_entry_table_lock, &state);
    for (index = 1; index < RTL_COUNT_OF(_ebpf_core_code_entry_table); index++)
    {
        if (!_ebpf_core_code_entry_table[index])
        {
            handle = index;
            _ebpf_core_code_entry_table[index] = code;
            break;
        }
    }
    ebpf_lock_unlock(&_ebpf_core_map_entry_table_lock, &state);
    return handle;
}

static ebpf_error_code_t _ebpf_core_set_hook_entry(ebpf_core_code_entry_t* code, ebpf_program_type_t program_type)
{
    ebpf_lock_state_t state;
    if (program_type > EBPF_PROGRAM_TYPE_BIND || program_type <= EBPF_PROGRAM_TYPE_UNSPECIFIED)
    {
        return EBPF_ERROR_INVALID_PARAMETER;
    }
    ebpf_lock_lock(&_ebpf_core_hook_table_lock, &state);
    _ebpf_core_hook_table[program_type] = code;
    ebpf_lock_unlock(&_ebpf_core_hook_table_lock, &state);
    return EBPF_ERROR_SUCCESS;
}

static ebpf_core_code_entry_t* _ebpf_core_get_hook_entry(ebpf_program_type_t program_type)
{
    ebpf_core_code_entry_t* code = NULL;
    ebpf_lock_state_t state;
    if (program_type > EBPF_PROGRAM_TYPE_BIND || program_type <= EBPF_PROGRAM_TYPE_UNSPECIFIED)
    {
        return NULL;
    }
    ebpf_lock_lock(&_ebpf_core_hook_table_lock, &state);
    code = _ebpf_core_hook_table[program_type];
    ebpf_lock_unlock(&_ebpf_core_hook_table_lock, &state);
    return code;
}

static ebpf_core_map_t* _ebpf_core_find_map_entry(uint64_t handle)
{
    ebpf_core_map_t* map;
    if (handle > RTL_COUNT_OF(_ebpf_core_map_entry_table))
    {
        return NULL;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_map_entry_table_lock, &state);
    map = _ebpf_core_map_entry_table[handle];
    ebpf_lock_unlock(&_ebpf_core_map_entry_table_lock, &state);
    return map;
}

static ebpf_core_code_entry_t* _ebpf_core_find_user_code(uint64_t handle)
{
    ebpf_core_code_entry_t* code;
    if (handle > RTL_COUNT_OF(_ebpf_core_code_entry_table))
    {
        return NULL;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_code_entry_table_lock, &state);
    code = _ebpf_core_code_entry_table[handle];
    ebpf_lock_unlock(&_ebpf_core_code_entry_table_lock, &state);
    return code;
}

static ebpf_error_code_t _ebpf_core_delete_map_entry(uint64_t handle)
{
    ebpf_core_map_t* map;
    if (handle > RTL_COUNT_OF(_ebpf_core_map_entry_table))
    {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_map_entry_table_lock, &state);
    map = _ebpf_core_map_entry_table[handle];
    if (map)
    {
        ebpf_map_function_tables[map->ebpf_map_definition.type].delete_map(map);
        _ebpf_core_map_entry_table[handle] = NULL;
    }
    ebpf_lock_unlock(&_ebpf_core_map_entry_table_lock, &state);
    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t _ebpf_core_delete_code_entry(uint64_t handle)
{
    ebpf_error_code_t retval = EBPF_ERROR_NOT_FOUND;
    ebpf_core_code_entry_t* code;
    if (handle > RTL_COUNT_OF(_ebpf_core_code_entry_table))
    {
        return EBPF_ERROR_INVALID_PARAMETER;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_code_entry_table_lock, &state);
    code = _ebpf_core_code_entry_table[handle];
    if (code)
    {
        if (code && code->code_type == EBPF_CODE_EBPF)
        {
            ubpf_destroy(code->vm);
        }

        ebpf_free(code);
        _ebpf_core_code_entry_table[handle] = NULL;
        retval = EBPF_ERROR_SUCCESS;
    }
    ebpf_lock_unlock(&_ebpf_core_code_entry_table_lock, &state);
    return retval;
}

ebpf_error_code_t
ebpf_core_initialize()
{
    ebpf_lock_create(&_ebpf_core_code_entry_table_lock);
    ebpf_lock_create(&_ebpf_core_map_entry_table_lock);
    return EBPF_ERROR_SUCCESS;
}

void
ebpf_core_terminate()
{
    size_t index;
    for (index = 0; index < RTL_COUNT_OF(_ebpf_core_map_entry_table); index++)
    {
        _ebpf_core_delete_map_entry(index);
    }
    for (index = 0; index < RTL_COUNT_OF(_ebpf_core_map_entry_table); index++)
    {
        _ebpf_core_delete_code_entry(index);
    }
}

ebpf_error_code_t
ebpf_core_protocol_attach_code(
    _In_ const struct _ebpf_operation_attach_detach_request* request,
    _Inout_ void* reply
)
{
    ebpf_error_code_t retval = EBPF_ERROR_NOT_FOUND;
    ebpf_core_code_entry_t* code = NULL;

    switch (request->hook)
    {
    case EBPF_PROGRAM_TYPE_XDP:
    case EBPF_PROGRAM_TYPE_BIND:
        break;
    default:
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    code = _ebpf_core_find_user_code(request->handle);
    if (code)
    {
        code->hook_point = request->hook;
        _ebpf_core_set_hook_entry(code, code->hook_point);
        retval = EBPF_ERROR_SUCCESS;
    }

Done:
    return retval;
}

ebpf_error_code_t
ebpf_core_protocol_detach_code(
    _In_ const struct _ebpf_operation_attach_detach_request* request,
    _Inout_ void* reply
)
{
    ebpf_error_code_t retval = EBPF_ERROR_NOT_FOUND;
    ebpf_core_code_entry_t* code = NULL;

    code = _ebpf_core_find_user_code(request->handle);
    if (code)
    {
        _ebpf_core_set_hook_entry(NULL, code->hook_point);
        code->hook_point = EBPF_PROGRAM_TYPE_UNSPECIFIED;
        retval = EBPF_ERROR_SUCCESS;
    }

    return retval;
}

ebpf_error_code_t
ebpf_core_protocol_unload_code(
    _In_ const struct _ebpf_operation_unload_code_request* request,
    _Inout_ void* reply)
{
    return _ebpf_core_delete_code_entry(request->handle);
}

ebpf_error_code_t
ebpf_core_protocol_load_code(
    _In_ const ebpf_operation_load_code_request_t* request,
    _Inout_ struct _ebpf_operation_load_code_reply* reply)
{
    ebpf_error_code_t retval;
    size_t code_size = request->header.length - RTL_OFFSET_OF(ebpf_operation_load_code_request_t, code);
    size_t allocation_size = 0;
    ebpf_core_code_entry_t* code = NULL;
    retval = ebpf_safe_size_t_add(code_size, sizeof(ebpf_core_code_entry_t), &allocation_size);
    if (retval != EBPF_ERROR_SUCCESS)
    {
        goto Done;
    }

    code = ebpf_allocate(allocation_size, EBPF_MEMORY_EXECUTE);
    if (!code)
    {
        retval = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }
    code->code = (uint8_t*)(code + 1);

    if (request->code_type == EBPF_CODE_NATIVE)
    {
        code->code_type = EBPF_CODE_NATIVE;
        memcpy(code->code, request->code, request->header.length - RTL_OFFSET_OF(ebpf_operation_load_code_request_t, code));
    }
    else
    {
        char* error_message;
        code->code_type = EBPF_CODE_EBPF;
        code->vm = ubpf_create();
        if (!code->vm)
        {
            retval = EBPF_ERROR_OUT_OF_RESOURCES; 
            goto Done;
        }
        ubpf_register_helper_resolver(code->vm, code, ebpf_core_interpreter_helper_resolver);
        if (ubpf_load(code->vm, &request->code[0], (uint32_t)code_size, &error_message) != 0)
        {
            retval = EBPF_ERROR_INVALID_PARAMETER;
            goto Done;
        }
    }

    reply->handle = _ebpf_core_insert_code_entry(code);

    retval = reply->handle != UINT64_MAX ? EBPF_ERROR_SUCCESS : EBPF_ERROR_OUT_OF_RESOURCES;

Done:
    if (retval != EBPF_ERROR_SUCCESS)
    {
        if (code && code->code_type == EBPF_CODE_EBPF)
        {
            ubpf_destroy(code->vm);
        }
        ebpf_free(code);
    }
    return retval;
}

ebpf_error_code_t ebpf_core_protocol_resolve_helper(
    _In_ const struct _ebpf_operation_resolve_helper_request* request,
    _Inout_ struct _ebpf_operation_resolve_helper_reply* reply)
{
    if (request->helper_id[0] >= RTL_COUNT_OF(_ebpf_program_helpers))
    {
        return EBPF_ERROR_INVALID_PARAMETER;
    }
    reply->address[0] = (uint64_t)_ebpf_program_helpers[request->helper_id[0]];

    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t ebpf_core_protocol_resolve_map(
    _In_ const struct _ebpf_operation_resolve_map_request* request,
    _Inout_ struct _ebpf_operation_resolve_map_reply* reply)
{
    ebpf_core_map_t* map;

    map = _ebpf_core_find_map_entry(request->map_handle[0]);
    if (map)
    {
        reply->address[0] = (uint64_t)map;
        return EBPF_ERROR_SUCCESS;
    }
    else
    {
        return EBPF_ERROR_NOT_FOUND;
    }
}

ebpf_error_code_t ebpf_core_invoke_hook(
    _In_ ebpf_program_type_t hook_point,
    _Inout_ void* context,
    _Inout_ uint32_t* result)
{
    ebpf_core_code_entry_t* code = NULL;
    ebpf_hook_function function_pointer;
    char* error_message;

    code = _ebpf_core_get_hook_entry(hook_point);
    if (code)
    {
        if (code->code_type == EBPF_CODE_NATIVE)
        {
            function_pointer = (ebpf_hook_function)(code->code);
            *result = (function_pointer)(context);
            return EBPF_ERROR_SUCCESS;
        }
        else
        {
            *result = (uint32_t)(ubpf_exec(code->vm, context, 1024, &error_message));
            if (error_message)
            {
                ebpf_free(error_message);
            }
            return EBPF_ERROR_SUCCESS;
        }
    }
    return EBPF_ERROR_NOT_FOUND;
}

ebpf_error_code_t ebpf_core_protocol_create_map(
    _In_ const struct _ebpf_operation_create_map_request* request,
    _Inout_ struct _ebpf_operation_create_map_reply* reply)
{
    ebpf_error_code_t retval;
    ebpf_core_map_t* map = NULL;

    size_t type = request->ebpf_map_definition.type;

    if (type >= RTL_COUNT_OF(ebpf_map_function_tables))
    {
        return EBPF_ERROR_NOT_FOUND;
    }

    if (ebpf_map_function_tables[type].create_map == NULL)
    {
        retval = EBPF_ERROR_NOT_FOUND;
        goto Done;
    }

    map = ebpf_map_function_tables[type].create_map(&request->ebpf_map_definition);
    if (map == NULL)
    {
        retval = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }

    reply->handle = _ebpf_core_insert_map_entry(map);
    if (reply->handle == UINT64_MAX)
    {
        retval = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }
    map = NULL;

    retval = EBPF_ERROR_SUCCESS;

Done:
    if (map != NULL)
    {
        ebpf_map_function_tables[type].delete_map(map);
    }

    return retval;
}

ebpf_error_code_t ebpf_core_protocol_map_lookup_element(
    _In_ const ebpf_operation_map_lookup_element_request_t* request,
    _Inout_ ebpf_operation_map_lookup_element_reply_t* reply)
{
    ebpf_error_code_t retval;
    ebpf_core_map_t* map = NULL;
    size_t type;
    uint8_t* value = NULL;

    map = _ebpf_core_find_map_entry(request->handle);
    if (!map)
    {
        retval = EBPF_ERROR_NOT_FOUND;
        goto Done;
    }

    type = map->ebpf_map_definition.type;
    
    if (request->header.length < (RTL_OFFSET_OF(ebpf_operation_map_lookup_element_request_t, key) + map->ebpf_map_definition.key_size))
    {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    if (reply->header.length < (RTL_OFFSET_OF(ebpf_operation_map_lookup_element_reply_t, value) + map->ebpf_map_definition.value_size))
    {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    value = ebpf_map_function_tables[type].lookup_entry(map, request->key);
    if (value == NULL)
    {
        retval = EBPF_ERROR_NOT_FOUND;
        goto Done;
    }
    
    memcpy(reply->value, value, map->ebpf_map_definition.value_size);
    retval = EBPF_ERROR_SUCCESS;

Done:    
    return retval;
}

ebpf_error_code_t ebpf_core_protocol_map_update_element(
    _In_ const epf_operation_map_update_element_request_t* request,
    _Inout_ void* reply)
{
    ebpf_error_code_t retval;
    ebpf_core_map_t* map = NULL;
    size_t type;

    map = _ebpf_core_find_map_entry(request->handle);
    if (!map)
    {
        retval = EBPF_ERROR_NOT_FOUND; 
        goto Done;
    }
    
    type = map->ebpf_map_definition.type;

    if (request->header.length < (RTL_OFFSET_OF(epf_operation_map_update_element_request_t, data) + map->ebpf_map_definition.key_size + map->ebpf_map_definition.value_size))
    {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    retval = ebpf_map_function_tables[type].update_entry(map, request->data, request->data + map->ebpf_map_definition.key_size);

Done:
    return retval;
}

ebpf_error_code_t ebpf_core_protocol_map_delete_element(
    _In_ const ebpf_operation_map_delete_element_request_t* request,
    _Inout_ void* reply)
{
    ebpf_error_code_t retval;
    ebpf_core_map_t* map = NULL;
    size_t type;

    map = _ebpf_core_find_map_entry(request->handle);
    if (!map)
    {
        retval = EBPF_ERROR_NOT_FOUND;
        goto Done;
    }

    type = map->ebpf_map_definition.type;

    if (request->header.length < (RTL_OFFSET_OF(ebpf_operation_map_delete_element_request_t, key) + map->ebpf_map_definition.key_size))
    {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    retval = ebpf_map_function_tables[type].delete_entry(map, request->key);

Done:
    return retval;
}

ebpf_error_code_t
ebpf_core_protocol_enumerate_maps(
    _In_ const struct _ebpf_operation_enumerate_maps_request* request,
    _Inout_ struct _ebpf_operation_enumerate_maps_reply* reply)
{
    uint64_t current_handle = request->previous_handle;

    // Start search from begining
    if (current_handle == UINT64_MAX)
    {
        current_handle = 1;
    }

    ebpf_lock_state_t state;
    ebpf_lock_lock(&_ebpf_core_map_entry_table_lock, &state);
    for (; current_handle < RTL_COUNT_OF(_ebpf_core_map_entry_table); current_handle++)
    {
        if (_ebpf_core_map_entry_table[current_handle] != NULL)
        {
            break;
        }
    }
    ebpf_lock_unlock(&_ebpf_core_map_entry_table_lock, &state);

    // No more handles, return end
    if (current_handle == RTL_COUNT_OF(_ebpf_core_map_entry_table))
    {
        current_handle = UINT64_MAX;
    }
    
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_core_protocol_query_map_definition(
    _In_ const struct _ebpf_operation_query_map_definition_request* request,
    _Inout_ struct _ebpf_operation_query_map_definition_reply* reply)
{
    ebpf_error_code_t retval = EBPF_ERROR_NOT_FOUND;
    ebpf_core_map_t* map = NULL;

    map = _ebpf_core_find_map_entry(request->handle);
    if (map)
    {
        reply->map_definition = map->ebpf_map_definition;
        retval = EBPF_ERROR_SUCCESS;
    }

    return retval;
}

void* _ebpf_core_map_lookup_element(ebpf_core_map_t* map, const uint8_t* key)
{
    size_t type = map->ebpf_map_definition.type;
    return ebpf_map_function_tables[type].lookup_entry(map, key);
}

void _ebpf_core_map_update_element(ebpf_core_map_t* map, const uint8_t* key, const uint8_t* value)
{
    size_t type = map->ebpf_map_definition.type;
    ebpf_map_function_tables[type].update_entry(map, key, value);
}

void _ebpf_core_map_delete_element(ebpf_core_map_t* map, const uint8_t* key)
{
    size_t type = map->ebpf_map_definition.type;
    ebpf_map_function_tables[type].delete_entry(map, key);
}

static uint64_t ebpf_core_interpreter_helper_resolver(void* context, uint32_t helper_id)
{
    if (helper_id >= RTL_COUNT_OF(_ebpf_program_helpers))
    {
        return 0;
    }
    return (uint64_t)_ebpf_program_helpers[helper_id];
}