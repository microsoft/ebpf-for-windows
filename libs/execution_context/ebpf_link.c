// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_link.h"
#include "ebpf_object.h"
#include "ebpf_platform.h"
#include "ebpf_program.h"

typedef struct _ebpf_link
{
    ebpf_object_t object;
    ebpf_program_t* program;
    ebpf_list_entry_t attach_list_entry;

    ebpf_attach_type_t attach_type;
    ebpf_program_type_t program_type;
    ebpf_extension_data_t client_data;
    ebpf_extension_client_t* extension_client_context;

    void* provider_binding_context;
} ebpf_link_t;

static ebpf_result_t
_ebpf_link_instance_invoke(
    _In_ const void* extension_client_binding_context, _In_ void* program_context, _Out_ uint32_t* result);

static struct
{
    size_t size;
    _ebpf_extension_dispatch_function function[1];
} _ebpf_link_dispatch_table = {1, {_ebpf_link_instance_invoke}};

static void
_ebpf_link_free(ebpf_object_t* object)
{
    ebpf_link_t* link = (ebpf_link_t*)object;
    ebpf_extension_unload(link->extension_client_context);
    ebpf_free(link->client_data.data);
    ebpf_epoch_free(link);
}

ebpf_result_t
ebpf_link_create(ebpf_link_t** link)
{
    *link = ebpf_epoch_allocate(sizeof(ebpf_link_t));
    if (*link == NULL)
        return EBPF_NO_MEMORY;

    memset(*link, 0, sizeof(ebpf_link_t));

    ebpf_object_initialize(&(*link)->object, EBPF_OBJECT_LINK, _ebpf_link_free);
    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_link_initialize(
    ebpf_link_t* link, ebpf_attach_type_t attach_type, const uint8_t* context_data, size_t context_data_length)
{
    ebpf_result_t return_value;
    ebpf_extension_data_t* provider_data;
    ebpf_attach_provider_data_t* attach_provider_data;

    link->client_data.version = 0;
    link->client_data.size = context_data_length;

    if (context_data_length > 0) {
        link->client_data.data = ebpf_allocate(context_data_length);
        if (!link->client_data.data) {
            return_value = EBPF_NO_MEMORY;
            goto Exit;
        }
        memcpy(&link->client_data.data, context_data, context_data_length);
    }

    ebpf_list_initialize(&link->attach_list_entry);

    return_value = ebpf_extension_load(
        &(link->extension_client_context),
        &attach_type,
        link,
        &link->client_data,
        (ebpf_extension_dispatch_table_t*)&_ebpf_link_dispatch_table,
        &(link->provider_binding_context),
        &provider_data,
        NULL,
        NULL);

    if (!provider_data) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    if ((provider_data->version != EBPF_ATTACH_PROVIDER_DATA_VERSION) || (!provider_data->data) ||
        (provider_data->size != sizeof(ebpf_attach_provider_data_t))) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    attach_provider_data = (ebpf_attach_provider_data_t*)provider_data->data;
    link->program_type = attach_provider_data->supported_program_type;

Exit:
    return return_value;
}

ebpf_result_t
ebpf_link_attach_program(ebpf_link_t* link, ebpf_program_t* program)
{
    ebpf_result_t return_value = EBPF_SUCCESS;
    ebpf_program_parameters_t program_parameters;
    if (link->program) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    link->program = program;
    ebpf_program_add_link_to_list(program, link);

    // Take "attach" reference which will be released when detach is called.
    ebpf_object_acquire_reference((ebpf_object_t*)link);

    return_value = ebpf_program_get_properties(program, &program_parameters);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    if (memcmp(&program_parameters.program_type, &link->program_type, sizeof(link->program_type)) != 0) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

Done:
    return return_value;
}

void
ebpf_link_detach_program(ebpf_link_t* link)
{
    if (!link->program)
        return;

    ebpf_program_remove_link_from_list(link->program, link);
    link->program = NULL;
    // Release the "attach" reference.
    ebpf_object_release_reference((ebpf_object_t*)link);
}

void
ebpf_link_entry_detach_program(_Inout_ ebpf_list_entry_t* entry)
{
    ebpf_link_t* link = CONTAINING_RECORD(entry, ebpf_link_t, attach_list_entry);
    ebpf_link_detach_program(link);
}

void
ebpf_link_insert_to_attach_list(_Inout_ ebpf_list_entry_t* head, _Inout_ ebpf_link_t* link)
{
    ebpf_list_insert_tail(head, &link->attach_list_entry);
}

void
ebpf_link_remove_from_attach_list(_Inout_ ebpf_link_t* link)
{
    ebpf_list_remove_entry(&link->attach_list_entry);
}

static ebpf_result_t
_ebpf_link_instance_invoke(
    _In_ const void* extension_client_binding_context, _In_ void* program_context, _Out_ uint32_t* result)
{
    ebpf_result_t return_value;
    ebpf_link_t* link = (ebpf_link_t*)ebpf_extension_get_client_context(extension_client_binding_context);

    if (link == NULL) {
        return_value = EBPF_FAILED;
        goto Exit;
    }

    return_value = ebpf_epoch_enter();
    if (return_value != EBPF_SUCCESS)
        goto Exit;
    ebpf_program_invoke(link->program, program_context, result);
    ebpf_epoch_exit();

Exit:
    return return_value;
}
