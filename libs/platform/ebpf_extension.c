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
    NPI_MODULEID expected_provider_module_id;
    // Opaque pointer to extension client context, such as eBPF program or eBPF Link.
    void* extension_client_context;
    // Per-provider binding context with client.  We currently only support one.
    struct _ebpf_extension_client_binding_context* client_binding_context;
    const ebpf_extension_data_t* client_data;
    const ebpf_extension_dispatch_table_t* client_dispatch_table;
    EX_RUNDOWN_REF nmr_rundown_ref;
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
} ebpf_extension_provider_t;

typedef struct _ebpf_extension_provider_binding_context
{
    GUID client_module_id;
    void* callback_context;
    ebpf_handle_t nmr_binding_handle;
} ebpf_extension_provider_binding_context;

static ebpf_result_t
_ebpf_extension_client_notify_change(
    ebpf_extension_client_t* client_context, ebpf_extension_client_binding_context_t* client_binding_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    EBPF_LOG_ENTRY();
    if (client_context->extension_change_callback) {
        result = client_context->extension_change_callback(
            client_context->extension_client_context, client_binding_context->provider_data);
    }
    EBPF_RETURN_RESULT(result);
}

NTSTATUS
_ebpf_extension_client_attach_provider(
    HANDLE nmr_binding_handle,
    _Inout_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    ebpf_extension_client_t* local_client_context = (ebpf_extension_client_t*)client_context;
    ebpf_extension_client_binding_context_t* local_client_binding_context = NULL;
    bool rundown_ref_initialized = false;

    // Check that the provider module Id matches the client's expected provider module Id.
    ebpf_assert(provider_registration_instance->ModuleId != NULL);
    _Analysis_assume_(provider_registration_instance->ModuleId != NULL);

    if (memcmp(
            &provider_registration_instance->ModuleId->Guid,
            &local_client_context->expected_provider_module_id.Guid,
            sizeof(local_client_context->expected_provider_module_id.Guid)) != 0) {
        status = STATUS_NOINTERFACE;
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Provider module ID doesn't match expected",
            provider_registration_instance->ModuleId->Guid,
            local_client_context->expected_provider_module_id.Guid);
        goto Done;
    }

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

    // Only initialize the rundown reference after we know we are going to try to attach.
    ExInitializeRundownProtection(&local_client_context->nmr_rundown_ref);
    rundown_ref_initialized = true;

    local_client_binding_context =
        (ebpf_extension_client_binding_context_t*)ebpf_allocate(sizeof(ebpf_extension_client_binding_context_t));

    if (!local_client_binding_context) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    local_client_binding_context->provider_module_id = *provider_registration_instance->ModuleId;
    local_client_binding_context->provider_data =
        (ebpf_extension_data_t*)provider_registration_instance->NpiSpecificCharacteristics;
    local_client_binding_context->extension_client = local_client_context;

    local_client_context->client_binding_context = local_client_binding_context;

    ebpf_result_t result = _ebpf_extension_client_notify_change(local_client_context, local_client_binding_context);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_WARNING, EBPF_TRACELOG_KEYWORD_BASE, "Client notify change failed with error");

        status = STATUS_UNSUCCESSFUL;
        goto Done;
    }

    status = NmrClientAttachProvider(
        nmr_binding_handle,
        local_client_context->client_binding_context,
        local_client_context->client_dispatch_table,
        &local_client_binding_context->provider_binding_context,
        &local_client_binding_context->provider_dispatch_table);

    local_client_binding_context->provider_is_attached = NT_SUCCESS(status);

    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrClientAttachProvider, status);
        goto Done;
    }

Done:
    if (!NT_SUCCESS(status) && rundown_ref_initialized) {
        // Mark the nmr_rundown_ref as rundown if the attach fails.
        ExWaitForRundownProtectionRelease(&local_client_context->nmr_rundown_ref);
    }
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

    // The NMR model is async, but the only Windows run-down protection API available is a blocking API, so the
    // following call will block until all using threads are complete. This should be fixed in the future.
    // Issue: https://github.com/microsoft/ebpf-for-windows/issues/1854
    ExWaitForRundownProtectionRelease(&local_client_context->nmr_rundown_ref);

    _ebpf_extension_client_notify_change(local_client_context, local_client_binding_context);

    EBPF_RETURN_NTSTATUS(STATUS_SUCCESS);
}

static void
_ebpf_extension_client_cleanup_binding_context(_In_opt_ _Post_invalid_ void* client_binding_context)
{
    EBPF_LOG_ENTRY();
    if (client_binding_context != NULL) {
        ebpf_extension_client_binding_context_t* local_client_binding_context =
            (ebpf_extension_client_binding_context_t*)client_binding_context;
        ebpf_extension_client_t* local_client_context = local_client_binding_context->extension_client;

        ebpf_free(local_client_binding_context);
        local_client_context->client_binding_context = NULL;
    }

    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_extension_load(
    _Outptr_ ebpf_extension_client_t** client_context,
    _In_ const GUID* interface_id,
    _In_ const GUID* expected_provider_module_id,
    _In_ const GUID* client_module_id,
    _In_ const void* extension_client_context,
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

    // Initialize the client context's rundown reference.
    ExInitializeRundownProtection(&local_client_context->nmr_rundown_ref);
    // Mark the client context's rundown reference as rundown.
    ExWaitForRundownProtectionRelease(&local_client_context->nmr_rundown_ref);

    local_client_context->client_data = client_data;
    local_client_context->npi_id = *interface_id;
    local_client_context->extension_client_context = (void*)extension_client_context;
    local_client_context->client_module_id.Length = sizeof(local_client_context->client_module_id);
    local_client_context->client_module_id.Type = MIT_GUID;
    local_client_context->client_module_id.Guid = *client_module_id;
    local_client_context->expected_provider_module_id.Length =
        sizeof(local_client_context->expected_provider_module_id);
    local_client_context->expected_provider_module_id.Type = MIT_GUID;
    local_client_context->expected_provider_module_id.Guid = *expected_provider_module_id;
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

    // Set client_context prior to calling NmrRegisterClient() so that the client context is available to the
    // client attach provider callback.
    *client_context = local_client_context;
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

    if (provider_binding_context) {
        *provider_binding_context = local_client_binding_context->provider_binding_context;
    }

    if (provider_data != NULL) {
        *provider_data = local_client_binding_context->provider_data;
    }
    if (provider_dispatch_table != NULL) {
        *provider_dispatch_table = local_client_binding_context->provider_dispatch_table;
    }
    *client_context = local_client_context;
    local_client_context = NULL;
    return_value = EBPF_SUCCESS;

Done:
    if (local_client_context != NULL) {
        ebpf_free(local_client_context->client_binding_context);
    }
    ebpf_free(local_client_context);
    local_client_context = NULL;

    if (return_value != EBPF_SUCCESS) {
        *client_context = NULL;
    }

    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_extension_unload(_Frees_ptr_opt_ ebpf_extension_client_t* client_context)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    if (client_context != NULL) {
        status = NmrDeregisterClient(client_context->nmr_client_handle);
        if (status == STATUS_PENDING) {
            status = NmrWaitForClientDeregisterComplete(client_context->nmr_client_handle);
            if (!NT_SUCCESS(status)) {
                EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrWaitForClientDeregisterComplete, status);
            }
        } else {
            EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrDeregisterClient, status);
        }
        ebpf_free(client_context->client_binding_context);
        ebpf_free(client_context);
    }
    EBPF_RETURN_VOID();
}

void*
ebpf_extension_get_client_context(_In_ const void* extension_client_binding_context)
{
    // No function entry/exit logging here because this is called with every eBPF program invocation.
    void* local_extension_client_context = NULL;
    ebpf_extension_client_binding_context_t* local_client_binding_context =
        (ebpf_extension_client_binding_context_t*)extension_client_binding_context;
    ebpf_extension_client_t* local_client_context = local_client_binding_context->extension_client;
    if (local_client_context != NULL) {
        local_extension_client_context = local_client_context->extension_client_context;
    }

    return local_extension_client_context;
}

GUID
ebpf_extension_get_provider_guid(_In_ const void* extension_client_binding_context)
{
    ebpf_extension_client_t* local_client_context = (ebpf_extension_client_t*)extension_client_binding_context;
    return local_client_context->npi_id;
}

_Must_inspect_result_ ebpf_result_t
ebpf_provider_load(
    _Outptr_ ebpf_extension_provider_t** provider_context,
    _In_ const GUID* interface_id,
    _In_ const GUID* provider_module_id,
    _Inout_opt_ void* provider_binding_context,
    _In_opt_ const ebpf_extension_data_t* provider_data,
    _In_opt_ const ebpf_extension_dispatch_table_t* provider_dispatch_table,
    _Inout_opt_ void* callback_context,
    _In_ PNPI_PROVIDER_ATTACH_CLIENT_FN provider_attach_client_callback,
    _In_ PNPI_PROVIDER_DETACH_CLIENT_FN provider_detach_client_callback,
    _In_opt_ PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN provider_cleanup_binding_context_callback)
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

    provider_characteristics = &(local_provider_context->provider_characteristics);
    provider_registration_instance = &(provider_characteristics->ProviderRegistrationInstance);

    provider_characteristics->Version = 0;
    provider_characteristics->Length = sizeof(*provider_characteristics);
    provider_characteristics->ProviderAttachClient = provider_attach_client_callback;
    provider_characteristics->ProviderDetachClient = provider_detach_client_callback;
    provider_characteristics->ProviderCleanupBindingContext = provider_cleanup_binding_context_callback;

    provider_registration_instance->Version = 0;
    provider_registration_instance->Size = sizeof(*provider_registration_instance);
    provider_registration_instance->NpiId = &local_provider_context->npi_id;
    provider_registration_instance->ModuleId = &local_provider_context->provider_module_id;

    provider_registration_instance->NpiSpecificCharacteristics = local_provider_context->provider_data;

    status =
        NmrRegisterProvider(provider_characteristics, callback_context, &local_provider_context->nmr_provider_handle);
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
            if (!NT_SUCCESS(status)) {
                EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrWaitForProviderDeregisterComplete, status);
            }
        } else {
            EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NmrDeregisterProvider, status);
        }
    }

    ebpf_free(provider_context);
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ bool
ebpf_extension_reference_provider_data(_Inout_ ebpf_extension_client_t* client_context)
{
    return ExAcquireRundownProtection(&client_context->nmr_rundown_ref) != FALSE;
}

void
ebpf_extension_dereference_provider_data(_Inout_ ebpf_extension_client_t* client_context)
{
    ExReleaseRundownProtection(&client_context->nmr_rundown_ref);
}
