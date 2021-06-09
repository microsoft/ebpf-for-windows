/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#include "ebpf_platform.h"

typedef struct _ebpf_extension_client
{
    NPIID npi_id;
    NPI_CLIENT_CHARACTERISTICS client_characteristics;
    NPI_MODULEID client_id;
    void* client_binding_context;
    const ebpf_extension_data_t* client_data;
    const ebpf_extension_dispatch_table_t* client_dispatch_table;
    NPI_MODULEID provider_id;
    void* provider_binding_context;
    ebpf_extension_data_t* provider_data;
    ebpf_extension_dispatch_table_t* provider_dispatch_table;
    HANDLE nmr_client_handle;
    bool provider_is_attached;
    ebpf_extension_change_callback_t extension_change_callback;
} ebpf_extension_client_t;

typedef struct _ebpf_extension_provider
{
    NPIID npi_id;
    NPI_PROVIDER_CHARACTERISTICS provider_characteristics;
    NPI_MODULEID provider_id;
    void* provider_binding_context;
    const ebpf_extension_data_t* provider_data;
    const ebpf_extension_dispatch_table_t* provider_dispatch_table;
    HANDLE nmr_provider_handle;
    void* callback_context;
    ebpf_provider_client_attach_callback_t client_attach_callback;
    ebpf_provider_client_detach_callback_t client_detach_callback;
} ebpf_extension_provider_t;

typedef struct _ebpf_extension_provider_binding_context
{
    GUID client_id;
    void* callback_context;
    ebpf_provider_client_detach_callback_t client_detach_callback;
} ebpf_extension_provider_binding_context;

static void
_ebpf_extension_client_notify_change(ebpf_extension_client_t* client_context)
{
    if (client_context->extension_change_callback)
        client_context->extension_change_callback(
            client_context->client_binding_context,
            client_context->provider_binding_context,
            client_context->provider_data,
            client_context->provider_dispatch_table);
}

NTSTATUS
_ebpf_extension_client_attach_provider(
    HANDLE nmr_binding_handle, void* client_context, const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    NTSTATUS status;
    ebpf_extension_client_t* local_client_context = (ebpf_extension_client_t*)client_context;

    // Only permit one provider to attach.
    if (local_client_context->provider_data != NULL) {
        return STATUS_NOINTERFACE;
    }

    // Check that the interface matches.
    if (memcmp(
            provider_registration_instance->NpiId,
            &local_client_context->npi_id,
            sizeof(local_client_context->npi_id)) != 0) {
        return STATUS_NOINTERFACE;
    }

    local_client_context->provider_id = *provider_registration_instance->ModuleId;
    local_client_context->provider_data =
        (ebpf_extension_data_t*)provider_registration_instance->NpiSpecificCharacteristics;

    status = NmrClientAttachProvider(
        nmr_binding_handle,
        local_client_context,
        local_client_context->client_dispatch_table,
        &local_client_context->provider_binding_context,
        &local_client_context->provider_dispatch_table);

    local_client_context->provider_is_attached = NT_SUCCESS(status);

    _ebpf_extension_client_notify_change(local_client_context);

    return status;
}

NTSTATUS
_ebpf_extension_client_detach_provider(void* client_binding_context)
{
    ebpf_extension_client_t* local_client_context = (ebpf_extension_client_t*)client_binding_context;

    local_client_context->provider_binding_context = NULL;
    local_client_context->provider_dispatch_table = NULL;
    local_client_context->provider_data = NULL;

    _ebpf_extension_client_notify_change(local_client_context);

    return STATUS_SUCCESS;
}

void
_ebpf_extension_client_cleanup_binding_context(void* client_binding_context)
{
    UNREFERENCED_PARAMETER(client_binding_context);
}

ebpf_result_t
ebpf_extension_load(
    _Outptr_ ebpf_extension_client_t** client_context,
    _In_ const GUID* interface_id,
    _In_ void* client_binding_context,
    _In_ const ebpf_extension_data_t* client_data,
    _In_ const ebpf_extension_dispatch_table_t* client_dispatch_table,
    _In_ void** provider_binding_context,
    _Outptr_ const ebpf_extension_data_t** provider_data,
    _Outptr_ const ebpf_extension_dispatch_table_t** provider_dispatch_table,
    _In_ ebpf_extension_change_callback_t extension_changed)
{
    ebpf_result_t return_value;
    ebpf_extension_client_t* local_client_context;
    NPI_CLIENT_CHARACTERISTICS* client_characteristics;
    NPI_REGISTRATION_INSTANCE* client_registration_instance;
    NTSTATUS status;

    local_client_context = ebpf_allocate(sizeof(ebpf_extension_client_t));

    if (!local_client_context) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(local_client_context, 0, sizeof(ebpf_extension_client_t));

    local_client_context->client_data = client_data;
    local_client_context->npi_id = *interface_id;
    local_client_context->client_binding_context = client_binding_context;
    local_client_context->client_id.Length = sizeof(local_client_context->client_id);
    local_client_context->client_id.Type = MIT_GUID;
    local_client_context->client_dispatch_table = client_dispatch_table;
    local_client_context->extension_change_callback = extension_changed;

    status = ExUuidCreate(&local_client_context->client_id.Guid);
    if (!NT_SUCCESS(status)) {
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    client_characteristics = &(local_client_context->client_characteristics);
    client_registration_instance = &(client_characteristics->ClientRegistrationInstance);

    client_characteristics->Version = 0;
    client_characteristics->Length = sizeof(*client_characteristics);
    client_characteristics->ClientAttachProvider = _ebpf_extension_client_attach_provider;
    client_characteristics->ClientDetachProvider = _ebpf_extension_client_detach_provider;
    client_characteristics->ClientCleanupBindingContext = _ebpf_extension_client_cleanup_binding_context;

    client_registration_instance->Version = 0;
    client_registration_instance->Size = sizeof(*client_registration_instance);
    client_registration_instance->NpiId = &local_client_context->npi_id;
    client_registration_instance->ModuleId = &local_client_context->client_id;

    client_registration_instance->NpiSpecificCharacteristics = &local_client_context->client_data;

    status = NmrRegisterClient(client_characteristics, local_client_context, &local_client_context->nmr_client_handle);
    if (!NT_SUCCESS(status)) {
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    if (!local_client_context->provider_is_attached) {
        ebpf_extension_unload(local_client_context);
        local_client_context = NULL;
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    *provider_binding_context = local_client_context->provider_binding_context;
    *provider_data = local_client_context->provider_data;
    *provider_dispatch_table = local_client_context->provider_dispatch_table;
    *client_context = local_client_context;
    local_client_context = NULL;
    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(local_client_context);
    return return_value;
}

void
ebpf_extension_unload(_Pre_maybenull_ _Post_invalid_ ebpf_extension_client_t* client_context)
{
    NTSTATUS status;
    if (client_context) {
        status = NmrDeregisterClient(client_context->nmr_client_handle);
        if (status == STATUS_PENDING)
            NmrWaitForClientDeregisterComplete(client_context->nmr_client_handle);
    }

    ebpf_free(client_context);
}

NTSTATUS
_ebpf_extension_provider_attach_client(
    HANDLE nmr_binding_handle,
    PVOID provider_context,
    const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    void* client_binding_context,
    const void* client_dispatch,
    void** provider_binding_context,
    const void** provider_dispatch)
{
    NTSTATUS status;
    ebpf_result_t return_value;
    ebpf_extension_provider_t* local_provider_context = (ebpf_extension_provider_t*)provider_context;
    ebpf_extension_provider_binding_context* local_provider_binding_context = NULL;
    UNREFERENCED_PARAMETER(nmr_binding_handle);
    ebpf_extension_client_t* local_extension_client = (ebpf_extension_client_t*)client_binding_context;
    // Check that the interface matches.
    if (memcmp(
            client_registration_instance->NpiId,
            &local_provider_context->npi_id,
            sizeof(local_provider_context->npi_id)) != 0) {
        status = STATUS_NOINTERFACE;
        goto Done;
    }

    local_provider_binding_context =
        (ebpf_extension_provider_binding_context*)ebpf_allocate(sizeof(ebpf_extension_provider_binding_context));

    if (!local_provider_binding_context) {
        status = STATUS_NOINTERFACE;
        goto Done;
    }

    local_provider_binding_context->client_id = client_registration_instance->ModuleId->Guid;
    local_provider_binding_context->callback_context = local_provider_context->callback_context;
    local_provider_binding_context->client_detach_callback = local_provider_context->client_detach_callback;

    if (local_provider_context->client_attach_callback) {
        return_value = local_provider_context->client_attach_callback(
            local_provider_context->callback_context,
            &local_provider_binding_context->client_id,
            local_extension_client->client_binding_context,
            (const ebpf_extension_data_t*)client_registration_instance->NpiSpecificCharacteristics,
            (const ebpf_extension_dispatch_table_t*)client_dispatch);

        if (return_value != EBPF_SUCCESS) {
            status = STATUS_NOINTERFACE;
            goto Done;
        }
    }

    *provider_binding_context = local_provider_binding_context;
    local_provider_binding_context = NULL;
    *provider_dispatch = local_provider_context->provider_dispatch_table;
    status = STATUS_SUCCESS;

Done:
    ebpf_free(local_provider_binding_context);
    return status;
}

NTSTATUS
_ebpf_extension_provider_detach_client(void* provider_binding_context)
{
    ebpf_extension_provider_binding_context* local_provider_binding_context =
        (ebpf_extension_provider_binding_context*)provider_binding_context;

    if (local_provider_binding_context->client_detach_callback)
        local_provider_binding_context->client_detach_callback(
            local_provider_binding_context->callback_context, &local_provider_binding_context->client_id);

    return STATUS_SUCCESS;
}

void
_ebpf_extension_provider_cleanup_binding_context(void* provider_binding_context)
{
    ebpf_free(provider_binding_context);
}

ebpf_result_t
ebpf_provider_load(
    _Outptr_ ebpf_extension_provider_t** provider_context,
    _In_ const GUID* interface_id,
    _In_ void* provider_binding_context,
    _In_ const ebpf_extension_data_t* provider_data,
    _In_ const ebpf_extension_dispatch_table_t* provider_dispatch_table,
    _In_ void* callback_context,
    _In_ ebpf_provider_client_attach_callback_t client_attach_callback,
    _In_ ebpf_provider_client_detach_callback_t client_detach_callback)
{
    ebpf_result_t return_value;
    ebpf_extension_provider_t* local_provider_context;
    NPI_PROVIDER_CHARACTERISTICS* provider_characteristics;
    NPI_REGISTRATION_INSTANCE* provider_registration_instance;
    NTSTATUS status;

    local_provider_context = ebpf_allocate(sizeof(ebpf_extension_provider_t));

    if (!local_provider_context) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(local_provider_context, 0, sizeof(ebpf_extension_provider_t));

    local_provider_context->provider_binding_context = provider_binding_context;
    local_provider_context->provider_data = provider_data;
    local_provider_context->npi_id = *interface_id;
    local_provider_context->provider_id.Length = sizeof(local_provider_context->provider_id);
    local_provider_context->provider_id.Type = MIT_GUID;
    local_provider_context->provider_dispatch_table = provider_dispatch_table;
    local_provider_context->callback_context = callback_context;
    local_provider_context->client_attach_callback = client_attach_callback;
    local_provider_context->client_detach_callback = client_detach_callback;

    status = ExUuidCreate(&local_provider_context->provider_id.Guid);
    if (!NT_SUCCESS(status)) {
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    provider_characteristics = &(local_provider_context->provider_characteristics);
    provider_registration_instance = &(provider_characteristics->ProviderRegistrationInstance);

    provider_characteristics->Version = 0;
    provider_characteristics->Length = sizeof(*provider_characteristics);
    provider_characteristics->ProviderAttachClient = _ebpf_extension_provider_attach_client;
    provider_characteristics->ProviderDetachClient = _ebpf_extension_provider_detach_client;
    provider_characteristics->ProviderCleanupBindingContext = _ebpf_extension_provider_cleanup_binding_context;

    provider_registration_instance->Version = 0;
    provider_registration_instance->Size = sizeof(*provider_registration_instance);
    provider_registration_instance->NpiId = &local_provider_context->npi_id;
    provider_registration_instance->ModuleId = &local_provider_context->provider_id;

    provider_registration_instance->NpiSpecificCharacteristics = local_provider_context->provider_data;

    status = NmrRegisterProvider(
        provider_characteristics, local_provider_context, &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status)) {
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    *provider_context = local_provider_context;
    local_provider_context = NULL;
    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(local_provider_context);
    return return_value;
}

void
ebpf_provider_unload(_Pre_maybenull_ _Post_invalid_ ebpf_extension_provider_t* provider_context)
{
    NTSTATUS status;
    if (provider_context) {
        status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
        if (status == STATUS_PENDING)
            NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
    }

    ebpf_free(provider_context);
}
