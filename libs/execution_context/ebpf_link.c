// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_object.h"
#include "ebpf_platform.h"
#include "ebpf_program.h"

typedef struct _ebpf_link
{
    ebpf_object_t object;
    ebpf_program_t* program;

    ebpf_attach_type_t attach_type;
    ebpf_program_type_t program_type;
    ebpf_extension_data_t client_data;
    ebpf_extension_client_t* extension_client_context;
    ebpf_lock_t attach_lock;

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
    ebpf_lock_destroy(&link->attach_lock);
    ebpf_epoch_free(link);
}

ebpf_result_t
ebpf_link_create(ebpf_link_t** link)
{
    *link = ebpf_epoch_allocate(sizeof(ebpf_link_t));
    if (*link == NULL)
        return EBPF_NO_MEMORY;

    memset(*link, 0, sizeof(ebpf_link_t));

    ebpf_result_t result = ebpf_object_initialize(&(*link)->object, EBPF_OBJECT_LINK, _ebpf_link_free, NULL);
    if (result != EBPF_SUCCESS) {
        ebpf_epoch_free(link);
        return result;
    }

    ebpf_lock_create(&(*link)->attach_lock);
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

    if (return_value != EBPF_SUCCESS) {
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
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&link->attach_lock);
    if (link->program) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    const ebpf_program_type_t* program_type = ebpf_program_type(program);
    if (memcmp(program_type, &link->program_type, sizeof(link->program_type)) != 0) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    link->program = program;
    ebpf_program_attach_link(program, link);

Done:
    ebpf_lock_unlock(&link->attach_lock, state);
    return return_value;
}

void
ebpf_link_detach_program(_Inout_ ebpf_link_t* link)
{
    ebpf_lock_state_t state;
    ebpf_program_t* program;

    state = ebpf_lock_lock(&link->attach_lock);
    if (!link->program) {
        ebpf_lock_unlock(&link->attach_lock, state);
        return;
    }

    program = link->program;
    link->program = NULL;
    ebpf_lock_unlock(&link->attach_lock, state);

    ebpf_program_detach_link(program, link);

    ebpf_extension_unload(link->extension_client_context);
    ebpf_free(link->client_data.data);
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

ebpf_result_t
ebpf_link_get_info(
    _In_ const ebpf_link_t* link, _Out_writes_to_(*info_size, *info_size) uint8_t* buffer, _Inout_ uint16_t* info_size)
{
    struct bpf_link_info* info = (struct bpf_link_info*)buffer;

    if (*info_size < sizeof(*info)) {
        return EBPF_INSUFFICIENT_BUFFER;
    }

    info->id = link->object.id;
    info->prog_id = (link->program) ? ((ebpf_object_t*)link->program)->id : EBPF_ID_NONE;
    info->type = BPF_LINK_TYPE_PLAIN;
    info->attach_type = BPF_ATTACH_TYPE_UNSPEC; // TODO(#223): get actual integer, and also return attach_type_uuid

    *info_size = sizeof(*info);
    return EBPF_SUCCESS;
}
