/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_link.h"

#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_epoch.h"
#include "ebpf_platform.h"

typedef struct _ebpf_link
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
} ebpf_link_t;

ebpf_error_code_t
_ebpf_link_instance_invoke(const ebpf_link_t* link, void* program_context, uint32_t* result);

static struct
{
    size_t size;
    _ebpf_extension_dispatch_function function[1];
} _ebpf_link_dispatch_table = {1, {_ebpf_link_instance_invoke}};

static void
_ebpf_link_free(ebpf_object_t* object)
{
    ebpf_link_t* link = (ebpf_link_t*)object;
    ebpf_link_detach_program(link);
    ebpf_extension_unload(link->extension_client_context);
    ebpf_free(link->client_data);
    ebpf_epoch_free(link);
}

ebpf_error_code_t
ebpf_link_create(ebpf_link_t** link)
{
    *link = ebpf_epoch_allocate(sizeof(ebpf_link_t), EBPF_MEMORY_NO_EXECUTE);
    if (*link == NULL)
        return EBPF_ERROR_OUT_OF_RESOURCES;

    memset(*link, 0, sizeof(ebpf_link_t));

    ebpf_object_initiate(&(*link)->object, EBPF_OBJECT_LINK, _ebpf_link_free);
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_link_initialize(
    ebpf_link_t* link, ebpf_attach_type_t attach_type, const uint8_t* context_data, size_t context_data_length)
{
    ebpf_error_code_t return_value;
    size_t client_data_length;

    ebpf_safe_size_t_add(sizeof(ebpf_extension_data_t), context_data_length, &client_data_length);

    link->client_data = ebpf_allocate(client_data_length, EBPF_MEMORY_NO_EXECUTE);
    if (!link->client_data)
        return EBPF_ERROR_OUT_OF_RESOURCES;

    link->client_data->version = 0;
    link->client_data->size = (uint16_t)client_data_length;
    memcpy(link->client_data->data, context_data, context_data_length);

    return_value = ebpf_extension_load(
        &(link->extension_client_context),
        &attach_type,
        link,
        link->client_data,
        (ebpf_extension_dispatch_table_t*)&_ebpf_link_dispatch_table,
        &(link->provider_binding_context),
        &(link->provider_data),
        &(link->provider_dispatch_table));

    return return_value;
}

ebpf_error_code_t
ebpf_link_get_properties(ebpf_link_t* link, uint8_t** hook_properties, size_t* hook_properties_length)
{
    if (!link->provider_data)
        return EBPF_ERROR_INVALID_PARAMETER;

    *hook_properties = link->provider_data->data;
    *hook_properties_length = link->provider_data->size;
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_link_attach_program(ebpf_link_t* link, ebpf_program_t* program)
{
    ebpf_error_code_t return_value;
    if (link->program) {
        return_value = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    link->program = program;
    ebpf_object_acquire_reference((ebpf_object_t*)program);

    return_value = ebpf_program_get_entry_point(program, &(link->program_entry_point));
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

Done:
    if (return_value != EBPF_ERROR_SUCCESS) {
        if (link->program == program) {
            ebpf_object_release_reference((ebpf_object_t*)program);
            link->program = NULL;
            link->program_entry_point = NULL;
        }
    }
    return return_value;
}

void
ebpf_link_detach_program(ebpf_link_t* link)
{
    if (!link->program)
        return;

    link->program_entry_point = NULL;
    ebpf_object_release_reference((ebpf_object_t*)link->program);
    link->program = NULL;
}

ebpf_error_code_t
_ebpf_link_instance_invoke(const ebpf_link_t* link, void* program_context, uint32_t* result)
{
    ebpf_error_code_t return_value;
    return_value = ebpf_epoch_enter();
    if (return_value != EBPF_ERROR_SUCCESS)
        return return_value;
    ebpf_program_invoke(link->program, program_context, result);
    ebpf_epoch_exit();
    return EBPF_ERROR_SUCCESS;
}