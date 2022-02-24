// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "net_ebpf_ext_prog_info_provider.h"

#include "ebpf_platform.h"
#include "ebpf_program_types.h"

/**
 *  @brief This is the per client binding context for program information
 *         NPI provider.
 */
typedef struct _net_ebpf_extension_program_info_client
{
    HANDLE nmr_binding_handle;
    GUID client_module_id;
} net_ebpf_extension_program_info_client_t;

/**
 *  @brief This is the program information NPI provider.
 */
typedef struct _net_ebpf_extension_program_info_provider
{
    HANDLE nmr_provider_handle;
} net_ebpf_extension_program_info_provider_t;

NTSTATUS
net_ebpf_extension_program_info_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_program_info_client_t* program_info_client = NULL;

    UNREFERENCED_PARAMETER(provider_context);
    UNREFERENCED_PARAMETER(client_dispatch);
    UNREFERENCED_PARAMETER(client_binding_context);

    if ((provider_binding_context == NULL) || (provider_dispatch == NULL)) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *provider_binding_context = NULL;
    *provider_dispatch = NULL;

    program_info_client = (net_ebpf_extension_program_info_client_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_program_info_client_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (program_info_client == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }
    memset(program_info_client, 0, sizeof(net_ebpf_extension_program_info_client_t));

    program_info_client->nmr_binding_handle = nmr_binding_handle;
    program_info_client->client_module_id = client_registration_instance->ModuleId->Guid;

Exit:
    if (NT_SUCCESS(status)) {
        *provider_binding_context = program_info_client;
        program_info_client = NULL;
    } else {
        if (program_info_client)
            ExFreePool(program_info_client);
    }
    return status;
}

NTSTATUS
net_ebpf_extension_program_info_provider_detach_client(_Frees_ptr_opt_ void* provider_binding_context)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (provider_binding_context)
        ExFreePool(provider_binding_context);

    return status;
}

void
net_ebpf_extension_program_info_provider_unregister(
    _Frees_ptr_opt_ net_ebpf_extension_program_info_provider_t* provider_context)
{
    if (provider_context != NULL) {
        NTSTATUS status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
        if (status == STATUS_PENDING)
            NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
        ExFreePool(provider_context);
    }
}

NTSTATUS
net_ebpf_extension_program_info_provider_register(
    _In_ const NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    _Outptr_ net_ebpf_extension_program_info_provider_t** provider_context)
{
    ebpf_extension_data_t* extension_data;
    ebpf_program_data_t* program_data;
    net_ebpf_extension_program_info_provider_t* local_provider_context = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    local_provider_context = (net_ebpf_extension_program_info_provider_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_program_info_provider_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (local_provider_context == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }
    memset(local_provider_context, 0, sizeof(net_ebpf_extension_program_info_provider_t));

    // For program info NPI, the NPI ID is assigned as the program type. Set it to the program_type_descriptor.
    extension_data =
        (ebpf_extension_data_t*)provider_characteristics->ProviderRegistrationInstance.NpiSpecificCharacteristics;
    program_data = (ebpf_program_data_t*)extension_data->data;
    program_data->program_info->program_type_descriptor.program_type =
        *(GUID*)provider_characteristics->ProviderRegistrationInstance.NpiId;

    status = NmrRegisterProvider(
        provider_characteristics, local_provider_context, &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status))
        goto Exit;

    *provider_context = local_provider_context;
    local_provider_context = NULL;

Exit:
    if (!NT_SUCCESS(status))
        net_ebpf_extension_program_info_provider_unregister(local_provider_context);

    return status;
}
