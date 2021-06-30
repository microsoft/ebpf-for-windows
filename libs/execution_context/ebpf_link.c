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

    ebpf_attach_type_t attach_type;
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
    ebpf_link_detach_program(link);
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

    link->client_data.version = 0;
    link->client_data.size = (uint16_t)context_data_length;

    if (context_data_length > 0) {
        link->client_data.data = ebpf_allocate(context_data_length);
        if (!link->client_data.data) {
            return_value = EBPF_NO_MEMORY;
            goto Exit;
        }
        memcpy(&link->client_data.data, context_data, context_data_length);
    }

    return_value = ebpf_extension_load(
        &(link->extension_client_context),
        &attach_type,
        link,
        &link->client_data,
        (ebpf_extension_dispatch_table_t*)&_ebpf_link_dispatch_table,
        &(link->provider_binding_context),
        NULL,
        NULL,
        NULL);

Exit:
    return return_value;
}

ebpf_result_t
ebpf_link_attach_program(ebpf_link_t* link, ebpf_program_t* program)
{
    ebpf_result_t return_value = EBPF_SUCCESS;
    if (link->program) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    link->program = program;
    ebpf_object_acquire_reference((ebpf_object_t*)program);

Done:
    if (return_value != EBPF_SUCCESS) {
        if (link->program == program) {
            ebpf_object_release_reference((ebpf_object_t*)program);
            link->program = NULL;
        }
    }
    return return_value;
}

void
ebpf_link_detach_program(ebpf_link_t* link)
{
    if (!link->program)
        return;

    ebpf_object_release_reference((ebpf_object_t*)link->program);
    link->program = NULL;
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
