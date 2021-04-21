/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_hook.h"

#include "ebpf_epoch.h"
#include "ebpf_platform.h"

typedef struct _ebpf_hook_instance
{
    volatile int32_t reference_count;
    ebpf_program_t* program;
    ebpf_program_entry_point program_entry_point;

    ebpf_attach_type_t attach_type;
    ebpf_extension_client_t* extension_client_context;

    uint8_t* hook_properties;
    size_t hook_properties_length;

    ebpf_extension_dispatch_table_t* provider_dispatch_table;
} ebpf_hook_instance_t;

// TODO: Get the actual GUID for the hook client.
static const GUID _ebpf_hook_client_id = {0};

ebpf_error_code_t
_ebpf_hook_instance_invoke(ebpf_hook_instance_t* hook, void* program_context);

static struct
{
    size_t size;
    _ebpf_extension_dispatch_function function[1];
} _ebpf_hook_dispatch_table = {1, {_ebpf_hook_instance_invoke}};

ebpf_error_code_t
ebpf_hook_instance_create(ebpf_hook_instance_t** hook)
{
    *hook = ebpf_epoch_allocate(sizeof(ebpf_hook_instance_t), EBPF_MEMORY_NO_EXECUTE);
    if (*hook == NULL)
        return EBPF_ERROR_OUT_OF_RESOURCES;

    memset(*hook, 0, sizeof(ebpf_hook_instance_t));

    (*hook)->reference_count = 1;
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_hook_instance_initialize(
    ebpf_hook_instance_t* hook, ebpf_attach_type_t attach_type, const uint8_t* context_data, size_t context_data_length)
{
    ebpf_error_code_t return_value;

    return_value = ebpf_extension_load(
        &(hook->extension_client_context),
        _ebpf_hook_client_id,
        context_data,
        context_data_length,
        (ebpf_extension_dispatch_table_t*)&_ebpf_hook_dispatch_table,
        attach_type,
        &(hook->hook_properties),
        &(hook->hook_properties_length),
        &(hook->provider_dispatch_table));

    return return_value;
}

ebpf_error_code_t
ebpf_hook_instance_get_properties(ebpf_hook_instance_t* hook, uint8_t** hook_properties, size_t* hook_properties_length)
{
    if (!hook->hook_properties)
        return EBPF_ERROR_INVALID_PARAMETER;

    *hook_properties = hook->hook_properties;
    *hook_properties_length = hook->hook_properties_length;
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
    ebpf_program_acquire_reference(program);

    return_value = ebpf_program_get_entry_point(program, &(hook->program_entry_point));
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

Done:
    if (return_value != EBPF_ERROR_SUCCESS) {
        if (hook->program == program) {
            ebpf_program_release_reference(program);
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
    ebpf_program_release_reference(hook->program);
    hook->program = NULL;
}

static void
_ebpf_hook_free(ebpf_hook_instance_t* hook)
{
    ebpf_hook_instance_detach_program(hook);
    ebpf_extension_unload(hook->extension_client_context);
    ebpf_epoch_free(hook);
}

void
ebpf_hook_instance_acquire_reference(ebpf_hook_instance_t* hook)
{
    ebpf_interlocked_increment_int32(&hook->reference_count);
}

void
ebpf_hook_instance_release_reference(ebpf_hook_instance_t* hook)
{
    int32_t new_ref_count = ebpf_interlocked_decrement_int32(&hook->reference_count);
    if (new_ref_count == 0)
        _ebpf_hook_free(hook);
}

ebpf_error_code_t
_ebpf_hook_instance_invoke(ebpf_hook_instance_t* hook, void* program_context)
{
    ebpf_error_code_t return_value;
    ebpf_epoch_enter();
    return_value = hook->program_entry_point(program_context);
    ebpf_epoch_exit();
    return return_value;
}