/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_hook.h"

#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_epoch.h"
#include "ebpf_platform.h"

typedef struct _ebpf_hook_instance
{
    ebpf_object_t object;
    ebpf_program_t* program;
    ebpf_program_entry_point_t program_entry_point;

    ebpf_attach_type_t attach_type;
    ebpf_extension_data_t* client_data;
    ebpf_extension_client_t* extension_client_context;

    void* provider_binding_context;
    ebpf_extension_data_t* provider_data;
    ebpf_extension_dispatch_table_t* provider_dispatch_table;
} ebpf_hook_instance_t;

ebpf_error_code_t
_ebpf_hook_instance_invoke(const ebpf_hook_instance_t* hook, void* program_context);

static struct
{
    size_t size;
    _ebpf_extension_dispatch_function function[1];
} _ebpf_hook_dispatch_table = {1, {_ebpf_hook_instance_invoke}};

static void
_ebpf_hook_free(ebpf_object_t* object)
{
    ebpf_hook_instance_t* hook = (ebpf_hook_instance_t*)object;
    ebpf_hook_instance_detach_program(hook);
    ebpf_extension_unload(hook->extension_client_context);
    ebpf_free(hook->client_data);
    ebpf_epoch_free(hook);
}

ebpf_error_code_t
ebpf_hook_instance_create(ebpf_hook_instance_t** hook)
{
    *hook = ebpf_epoch_allocate(sizeof(ebpf_hook_instance_t), EBPF_MEMORY_NO_EXECUTE);
    if (*hook == NULL)
        return EBPF_ERROR_OUT_OF_RESOURCES;

    memset(*hook, 0, sizeof(ebpf_hook_instance_t));

    ebpf_object_initiate(&(*hook)->object, EBPF_OBJECT_HOOK_INSTANCE, _ebpf_hook_free);
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_hook_instance_initialize(
    ebpf_hook_instance_t* hook, ebpf_attach_type_t attach_type, const uint8_t* context_data, size_t context_data_length)
{
    ebpf_error_code_t return_value;
    size_t client_data_length;

    ebpf_safe_size_t_add(sizeof(ebpf_extension_data_t), context_data_length, &client_data_length);

    hook->client_data = ebpf_allocate(client_data_length, EBPF_MEMORY_NO_EXECUTE);
    if (!hook->client_data)
        return EBPF_ERROR_OUT_OF_RESOURCES;

    hook->client_data->version = 0;
    hook->client_data->size = (uint16_t)client_data_length;
    memcpy(hook->client_data->data, context_data, context_data_length);

    return_value = ebpf_extension_load(
        &(hook->extension_client_context),
        &attach_type,
        hook,
        hook->client_data,
        (ebpf_extension_dispatch_table_t*)&_ebpf_hook_dispatch_table,
        &(hook->provider_binding_context),
        &(hook->provider_data),
        &(hook->provider_dispatch_table));

    return return_value;
}

ebpf_error_code_t
ebpf_hook_instance_get_properties(ebpf_hook_instance_t* hook, uint8_t** hook_properties, size_t* hook_properties_length)
{
    if (!hook->provider_data)
        return EBPF_ERROR_INVALID_PARAMETER;

    *hook_properties = hook->provider_data->data;
    *hook_properties_length = hook->provider_data->size;
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_hook_instance_attach_program(ebpf_hook_instance_t* hook, ebpf_program_t* program)
{
    ebpf_error_code_t return_value;
    if (hook->program) {
        return_value = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    hook->program = program;
    ebpf_object_acquire_reference((ebpf_object_t*)program);

    return_value = ebpf_program_get_entry_point(program, &(hook->program_entry_point));
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

Done:
    if (return_value != EBPF_ERROR_SUCCESS) {
        if (hook->program == program) {
            ebpf_object_release_reference((ebpf_object_t*)program);
            hook->program = NULL;
            hook->program_entry_point = NULL;
        }
    }
    return return_value;
}

void
ebpf_hook_instance_detach_program(ebpf_hook_instance_t* hook)
{
    if (!hook->program)
        return;

    hook->program_entry_point = NULL;
    ebpf_object_release_reference((ebpf_object_t*)hook->program);
    hook->program = NULL;
}

ebpf_error_code_t
_ebpf_hook_instance_invoke(const ebpf_hook_instance_t* hook, void* program_context)
{
    ebpf_error_code_t return_value;
    ebpf_epoch_enter();
    return_value = hook->program_entry_point(program_context);
    ebpf_epoch_exit();
    return return_value;
}