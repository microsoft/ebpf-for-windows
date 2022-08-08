// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_object.h"
#include "ebpf_platform.h"
#include "ebpf_program.h"

typedef struct _ebpf_link
{
    ebpf_core_object_t object;
    ebpf_program_t* program;

    ebpf_attach_type_t attach_type;
    bpf_attach_type_t bpf_attach_type;
    enum bpf_link_type link_type;
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
_ebpf_link_free(ebpf_core_object_t* object)
{
    ebpf_link_t* link = (ebpf_link_t*)object;
    ebpf_lock_destroy(&link->attach_lock);
    ebpf_epoch_free(link);
}

ebpf_result_t
ebpf_link_create(ebpf_link_t** link)
{
    EBPF_LOG_ENTRY();
    *link = ebpf_epoch_allocate(sizeof(ebpf_link_t));
    if (*link == NULL)
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);

    memset(*link, 0, sizeof(ebpf_link_t));

    ebpf_result_t result = ebpf_object_initialize(&(*link)->object, EBPF_OBJECT_LINK, _ebpf_link_free, NULL);
    if (result != EBPF_SUCCESS) {
        ebpf_epoch_free(link);
        EBPF_RETURN_RESULT(result);
    }

    ebpf_lock_create(&(*link)->attach_lock);
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

ebpf_result_t
ebpf_link_initialize(
    ebpf_link_t* link, ebpf_attach_type_t attach_type, const uint8_t* context_data, size_t context_data_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_extension_data_t* provider_data;
    ebpf_attach_provider_data_t* attach_provider_data;
    GUID module_id = {0};

    return_value = ebpf_guid_create(&module_id);
    if (return_value != EBPF_SUCCESS) {
        goto Exit;
    }

    link->client_data.version = 0;
    link->client_data.size = context_data_length;

    if (context_data_length > 0) {
        link->client_data.data = ebpf_allocate(context_data_length);
        if (!link->client_data.data) {
            return_value = EBPF_NO_MEMORY;
            goto Exit;
        }
        memcpy(link->client_data.data, context_data, context_data_length);
    }

    return_value = ebpf_extension_load(
        &(link->extension_client_context),
        &ebpf_hook_extension_interface_id, // Load hook extension.
        &attach_type,                      // Attach type is the expected provider module Id.
        &module_id,
        link,
        &link->client_data,
        (ebpf_extension_dispatch_table_t*)&_ebpf_link_dispatch_table,
        &(link->provider_binding_context),
        &provider_data,
        NULL,
        NULL);

    if (return_value != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_LINK, "No providers support attach type", attach_type);
        goto Exit;
    }

    if ((provider_data->version != EBPF_ATTACH_PROVIDER_DATA_VERSION) || (!provider_data->data) ||
        (provider_data->size != sizeof(ebpf_attach_provider_data_t))) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_LINK, "Provider version not supported", attach_type);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    attach_provider_data = (ebpf_attach_provider_data_t*)provider_data->data;
    link->program_type = attach_provider_data->supported_program_type;
    link->attach_type = attach_type;
    link->bpf_attach_type = attach_provider_data->bpf_attach_type;
    link->link_type = attach_provider_data->link_type;

Exit:
    EBPF_RETURN_RESULT(return_value);
}

ebpf_result_t
ebpf_link_attach_program(ebpf_link_t* link, ebpf_program_t* program)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value = EBPF_SUCCESS;
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&link->attach_lock);
    if (link->program) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    const ebpf_program_type_t* program_type = ebpf_program_type_uuid(program);
    if (memcmp(program_type, &link->program_type, sizeof(link->program_type)) != 0) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_LINK,
            "Attach failed due to incorrect program type",
            *program_type);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    link->program = program;
    ebpf_program_attach_link(program, link);

Done:
    ebpf_lock_unlock(&link->attach_lock, state);
    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_link_detach_program(_Inout_ ebpf_link_t* link)
{
    EBPF_LOG_ENTRY();
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
    link->client_data.data = NULL;
    link->client_data.size = 0;
    EBPF_RETURN_VOID();
}

static ebpf_result_t
_ebpf_link_instance_invoke(
    _In_ const void* extension_client_binding_context, _In_ void* program_context, _Out_ uint32_t* result)
{
    // No function entry exit traces as this is a high volume function.
    ebpf_result_t return_value;
    ebpf_link_t* link = (ebpf_link_t*)ebpf_extension_get_client_context(extension_client_binding_context);

    if (link == NULL) {
        GUID npi_id = ebpf_extension_get_provider_guid(extension_client_binding_context);
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_WARNING, EBPF_TRACELOG_KEYWORD_LINK, "Client context is null", npi_id);
        return_value = EBPF_FAILED;
        goto Exit;
    }

    return_value = ebpf_epoch_enter();
    if (return_value != EBPF_SUCCESS)
        goto Exit;
    ebpf_program_invoke(link->program, program_context, result);
    ebpf_epoch_exit();

Exit:
    EBPF_RETURN_RESULT(return_value);
}

ebpf_result_t
ebpf_link_get_info(
    _In_ const ebpf_link_t* link, _Out_writes_to_(*info_size, *info_size) uint8_t* buffer, _Inout_ uint16_t* info_size)
{
    EBPF_LOG_ENTRY();
    struct bpf_link_info* info = (struct bpf_link_info*)buffer;

    if (*info_size < sizeof(*info)) {
        EBPF_RETURN_RESULT(EBPF_INSUFFICIENT_BUFFER);
    }

    info->id = link->object.id;
    info->prog_id = (link->program) ? ((ebpf_core_object_t*)link->program)->id : EBPF_ID_NONE;
    info->type = link->link_type;
    info->program_type_uuid = link->program_type;
    info->attach_type_uuid = link->attach_type;
    info->attach_type = link->bpf_attach_type;

    // Copy any additional parameters.
    size_t size = sizeof(struct bpf_link_info) - FIELD_OFFSET(struct bpf_link_info, attach_data);
    if ((link->client_data.size > 0) && (link->client_data.size <= size)) {
        memcpy(&info->attach_data, link->client_data.data, link->client_data.size);
    }

    *info_size = sizeof(*info);
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}
