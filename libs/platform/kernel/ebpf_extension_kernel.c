// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"

// EBPF_RETURN_NTSTATUS(STATUS_SUCCESS) and similar macro invocations trigger C4127.
#pragma warning(disable : 4127) // conditional expression is constant

struct _ebpf_extension_client_binding_context;

typedef struct _ebpf_extension_client
{
    NPIID npi_id;
    NPI_CLIENT_CHARACTERISTICS client_characteristics;
    NPI_MODULEID client_module_id;
    // Opaque pointer to extension client context, such as eBPF program or eBPF Link.
    void* extension_client_context;
    // Per-provider binding context with client.
    struct _ebpf_extension_client_binding_context* client_binding_context;
    const ebpf_extension_data_t* client_data;
    const ebpf_extension_dispatch_table_t* client_dispatch_table;
    HANDLE nmr_client_handle;
    ebpf_extension_change_callback_t extension_change_callback;
} ebpf_extension_client_t;

typedef struct _ebpf_extension_client_binding_context
{
    NPI_MODULEID provider_module_id;
    void* provider_binding_context;
    ebpf_extension_data_t* provider_data;
    ebpf_extension_dispatch_table_t* provider_dispatch_table;
    bool provider_is_attached;
    ebpf_extension_client_t* extension_client;
} ebpf_extension_client_binding_context_t;

typedef struct _ebpf_extension_provider
{
    NPIID npi_id;
    NPI_PROVIDER_CHARACTERISTICS provider_characteristics;
    NPI_MODULEID provider_module_id;
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
    GUID client_module_id;
    void* callback_context;
    ebpf_provider_client_detach_callback_t client_detach_callback;
} ebpf_extension_provider_binding_context;

static void
_ebpf_extension_client_notify_change(
    ebpf_extension_client_t* client_context, ebpf_extension_client_binding_context_t* client_binding_context)
{
    EBPF_LOG_ENTRY();
    if (client_context->extension_change_callback)
        client_context->extension_change_callback(
            client_context->extension_client_context,
            client_binding_context->provider_binding_context,
            client_binding_context->provider_data);
    EBPF_RETURN_VOID();
}

NTSTATUS
_ebpf_extension_client_attach_provider(
    HANDLE nmr_binding_handle, void* client_context, const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    ebpf_extension_client_t* local_client_context = (ebpf_extension_client_t*)client_context;
    ebpf_extension_client_binding_context_t* local_client_binding_context = NULL;

    // Only permit one provider to attach.
    if (local_client_context->client_binding_context != NULL) {
        status = STATUS_NOINTERFACE;
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Client already attached to provider",
            *provider_registration_instance->NpiId)
        goto Done;
    }

    // Check that the interface matches.
    if (memcmp(
            provider_registration_instance->NpiId,
            &local_client_context->npi_id,
            sizeof(local_client_context->npi_id)) != 0) {
        status = STATUS_NOINTERFACE;
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Interface doesn't match",
            *provider_registration_instance->NpiId,
            local_client_context->npi_id);
        goto Done;
    }

    local_client_binding_context =
        (ebpf_extension_client_binding_context_t*)ebpf_allocate(sizeof(ebpf_extension_client_binding_context_t));

    if (!local_client_binding_context) {
        status = STATUS_NOINTERFACE;
        goto Done;
    }

    local_client_binding_context->provider_module_id = *provider_registration_instance->ModuleId;
    local_client_binding_context->provider_data =
        (ebpf_extension_data_t*)provider_registration_instance->NpiSpecificCharacteristics;
    local_client_binding_context->extension_client = local_client_context;

    local_client_context->client_binding_context = local_client_binding_context;

    status = NmrClientAttachProvider(
        nmr_binding_handle,
        local_client_context->client_binding_context,
        local_client_context->client_dispatch_table,
        &local_client_binding_context->provider_binding_context,
        &local_client_binding_context->provider_dispatch_table);

    local_client_binding_context->provider_is_attached = NT_SUCCESS(status);

    if (NT_SUCCESS(status))
        _ebpf_extension_client_notify_change(local_client_context, local_client_binding_context);
    else
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrClientAttachProvider, status);

Done:
    EBPF_RETURN_NTSTATUS(status);
}

NTSTATUS
_ebpf_extension_client_detach_provider(void* client_binding_context)
{
    EBPF_LOG_ENTRY();
    ebpf_extension_client_binding_context_t* local_client_binding_context =
        (ebpf_extension_client_binding_context_t*)client_binding_context;
    ebpf_extension_client_t* local_client_context = local_client_binding_context->extension_client;

    local_client_binding_context->provider_binding_context = NULL;
    local_client_binding_context->provider_dispatch_table = NULL;
    local_client_binding_context->provider_data = NULL;

    _ebpf_extension_client_notify_change(local_client_context, local_client_binding_context);

    ebpf_free(local_client_binding_context);
    local_client_context->client_binding_context = NULL;

    EBPF_RETURN_NTSTATUS(STATUS_SUCCESS);
}

void
_ebpf_extension_client_cleanup_binding_context(void* client_binding_context)
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(client_binding_context);
    EBPF_RETURN_VOID();
}

ebpf_result_t
ebpf_extension_load(
    _Outptr_ ebpf_extension_client_t** client_context,
    _In_ const GUID* interface_id,
    _In_ const GUID* client_module_id,
    _In_ void* extension_client_context,
    _In_opt_ const ebpf_extension_data_t* client_data,
    _In_opt_ const ebpf_extension_dispatch_table_t* client_dispatch_table,
    _Outptr_opt_ void** provider_binding_context,
    _Outptr_opt_ const ebpf_extension_data_t** provider_data,
    _Outptr_opt_ const ebpf_extension_dispatch_table_t** provider_dispatch_table,
    _In_opt_ ebpf_extension_change_callback_t extension_changed)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_extension_client_t* local_client_context = NULL;
    ebpf_extension_client_binding_context_t* local_client_binding_context = NULL;
    NPI_CLIENT_CHARACTERISTICS* client_characteristics;
    NPI_REGISTRATION_INSTANCE* client_registration_instance;
    NTSTATUS status;

    if (provider_binding_context == NULL) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    local_client_context = ebpf_allocate(sizeof(ebpf_extension_client_t));

    if (!local_client_context) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    local_client_context->client_data = client_data;
    local_client_context->npi_id = *interface_id;
    local_client_context->extension_client_context = extension_client_context;
    local_client_context->client_module_id.Length = sizeof(local_client_context->client_module_id);
    local_client_context->client_module_id.Type = MIT_GUID;
    local_client_context->client_module_id.Guid = *client_module_id;
    local_client_context->client_dispatch_table = client_dispatch_table;
    local_client_context->extension_change_callback = extension_changed;

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
    client_registration_instance->ModuleId = &local_client_context->client_module_id;

    client_registration_instance->NpiSpecificCharacteristics = local_client_context->client_data;

    status = NmrRegisterClient(client_characteristics, local_client_context, &local_client_context->nmr_client_handle);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrRegisterClient, status);
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    local_client_binding_context = local_client_context->client_binding_context;

    if (local_client_binding_context == NULL) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_BASE,
            "local_client_context->client_binding_context is NULL",
            *interface_id);
        ebpf_extension_unload(local_client_context);
        local_client_context = NULL;
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    if (!local_client_binding_context->provider_is_attached) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_BASE,
            "local_client_binding_context->provider_is_attached is FALSE",
            *interface_id);
        ebpf_extension_unload(local_client_context);
        local_client_context = NULL;
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    if (provider_binding_context)
        *provider_binding_context = local_client_binding_context->provider_binding_context;

    if (provider_data != NULL)
        *provider_data = local_client_binding_context->provider_data;
    if (provider_dispatch_table != NULL)
        *provider_dispatch_table = local_client_binding_context->provider_dispatch_table;
    *client_context = local_client_context;
    local_client_context = NULL;
    return_value = EBPF_SUCCESS;

Done:
    if (local_client_context != NULL)
        ebpf_free(local_client_context->client_binding_context);
    ebpf_free(local_client_context);
    local_client_context = NULL;
    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_extension_unload(_Frees_ptr_opt_ ebpf_extension_client_t* client_context)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    if (client_context) {
        status = NmrDeregisterClient(client_context->nmr_client_handle);
        if (status == STATUS_PENDING) {
            status = NmrWaitForClientDeregisterComplete(client_context->nmr_client_handle);
            if (!NT_SUCCESS(status)) {
                EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrWaitForClientDeregisterComplete, status);
            }
        } else
            EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrDeregisterClient, status);
    }
    if (client_context != NULL)
        ebpf_free(client_context->client_binding_context);
    ebpf_free(client_context);
    EBPF_RETURN_VOID();
}

void*
ebpf_extension_get_client_context(_In_ const void* extension_client_binding_context)
{
    EBPF_LOG_ENTRY();
    void* local_extension_client_context = NULL;
    ebpf_extension_client_binding_context_t* local_client_binding_context =
        (ebpf_extension_client_binding_context_t*)extension_client_binding_context;
    ebpf_extension_client_t* local_client_context = local_client_binding_context->extension_client;
    if (local_client_context != NULL)
        local_extension_client_context = local_client_context->extension_client_context;

    EBPF_RETURN_POINTER(void*, local_extension_client_context);
}

GUID
ebpf_extension_get_provider_guid(_In_ const void* extension_client_binding_context)
{
    ebpf_extension_client_t* local_client_context = (ebpf_extension_client_t*)extension_client_binding_context;
    return local_client_context->npi_id;
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
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    ebpf_result_t return_value;
    ebpf_extension_provider_t* local_provider_context = (ebpf_extension_provider_t*)provider_context;
    ebpf_extension_provider_binding_context* local_provider_binding_context = NULL;
    UNREFERENCED_PARAMETER(nmr_binding_handle);
    // Check that the interface matches.
    if (memcmp(
            client_registration_instance->NpiId,
            &local_provider_context->npi_id,
            sizeof(local_provider_context->npi_id)) != 0) {

        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Interface doesn't match",
            *client_registration_instance->NpiId,
            local_provider_context->npi_id);
        status = STATUS_NOINTERFACE;
        goto Done;
    }

    local_provider_binding_context =
        (ebpf_extension_provider_binding_context*)ebpf_allocate(sizeof(ebpf_extension_provider_binding_context));

    if (!local_provider_binding_context) {
        status = STATUS_NOINTERFACE;
        goto Done;
    }

    local_provider_binding_context->client_module_id = client_registration_instance->ModuleId->Guid;
    local_provider_binding_context->callback_context = local_provider_context->callback_context;
    local_provider_binding_context->client_detach_callback = local_provider_context->client_detach_callback;

    if (local_provider_context->client_attach_callback) {
        return_value = local_provider_context->client_attach_callback(
            local_provider_context->callback_context,
            &local_provider_binding_context->client_module_id,
            client_binding_context,
            (const ebpf_extension_data_t*)client_registration_instance->NpiSpecificCharacteristics,
            (const ebpf_extension_dispatch_table_t*)client_dispatch);

        if (return_value != EBPF_SUCCESS) {
            EBPF_LOG_MESSAGE_UINT64(
                EBPF_TRACELOG_LEVEL_WARNING,
                EBPF_TRACELOG_KEYWORD_BASE,
                "client_attach_callback return failure",
                return_value);
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
    EBPF_RETURN_NTSTATUS(STATUS_SUCCESS);
}

NTSTATUS
_ebpf_extension_provider_detach_client(void* provider_binding_context)
{
    EBPF_LOG_ENTRY();
    ebpf_extension_provider_binding_context* local_provider_binding_context =
        (ebpf_extension_provider_binding_context*)provider_binding_context;

    if (local_provider_binding_context->client_detach_callback)
        local_provider_binding_context->client_detach_callback(
            local_provider_binding_context->callback_context, &local_provider_binding_context->client_module_id);

    EBPF_RETURN_NTSTATUS(STATUS_SUCCESS);
}

void
_ebpf_extension_provider_cleanup_binding_context(void* provider_binding_context)
{
    EBPF_LOG_ENTRY();
    ebpf_free(provider_binding_context);
    EBPF_RETURN_VOID();
}

ebpf_result_t
ebpf_provider_load(
    _Outptr_ ebpf_extension_provider_t** provider_context,
    _In_ const GUID* interface_id,
    _In_ const GUID* provider_module_id,
    _In_opt_ void* provider_binding_context,
    _In_opt_ const ebpf_extension_data_t* provider_data,
    _In_opt_ const ebpf_extension_dispatch_table_t* provider_dispatch_table,
    _In_opt_ void* callback_context,
    _In_opt_ ebpf_provider_client_attach_callback_t client_attach_callback,
    _In_opt_ ebpf_provider_client_detach_callback_t client_detach_callback)
{
    EBPF_LOG_ENTRY();
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
    local_provider_context->provider_module_id.Length = sizeof(local_provider_context->provider_module_id);
    local_provider_context->provider_module_id.Type = MIT_GUID;
    local_provider_context->provider_module_id.Guid = *provider_module_id;
    local_provider_context->provider_dispatch_table = provider_dispatch_table;
    local_provider_context->callback_context = callback_context;
    local_provider_context->client_attach_callback = client_attach_callback;
    local_provider_context->client_detach_callback = client_detach_callback;

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
    provider_registration_instance->ModuleId = &local_provider_context->provider_module_id;

    provider_registration_instance->NpiSpecificCharacteristics = local_provider_context->provider_data;

    status = NmrRegisterProvider(
        provider_characteristics, local_provider_context, &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status)) {
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrRegisterProvider, status);
        goto Done;
    }

    *provider_context = local_provider_context;
    local_provider_context = NULL;
    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(local_provider_context);
    local_provider_context = NULL;
    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_provider_unload(_Frees_ptr_opt_ ebpf_extension_provider_t* provider_context)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    if (provider_context) {
        status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
        if (status == STATUS_PENDING) {
            status = NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
            if (!NT_SUCCESS(status))
                EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrWaitForProviderDeregisterComplete, status);
        } else
            EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrDeregisterProvider, status);
    }

    ebpf_free(provider_context);
    EBPF_RETURN_VOID();
}
