// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_extension_uuids.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "net_ebpf_ext_prog_info_provider.h"

/**
 *  @brief This is the per client binding context for program information
 *         NPI provider.
 */
typedef struct _net_ebpf_extension_program_info_client
{
    HANDLE nmr_binding_handle; ///< NMR binding handle.
    GUID client_module_id;     ///< NMR module Id.
} net_ebpf_extension_program_info_client_t;

/**
 *  @brief This is the program information NPI provider.
 */
typedef struct _net_ebpf_extension_program_info_provider
{
    NPI_PROVIDER_CHARACTERISTICS characteristics; ///< NPI Provider characteristics.
    HANDLE nmr_provider_handle;                   ///< NMR binding handle.
} net_ebpf_extension_program_info_provider_t;

/**
 * @brief Callback invoked when an eBPF Program Information NPI client attaches.
 *
 * @param[in] nmr_binding_handle NMR binding between the client module and the provider module.
 * @param[in] provider_context Provider module's context.
 * @param[in] client_registration_instance Client module's registration data.
 * @param[in] client_binding_context Client module's context for binding with provider.
 * @param[in] client_dispatch Client module's dispatch table. Contains the function pointer
 * to invoke the eBPF program.
 * @param[out] provider_binding_context Pointer to provider module's binding context with the client module.
 * @param[out] provider_dispatch Pointer to provider module's dispatch table.
 * @retval STATUS_SUCCESS The operation succeeded.
 * @retval STATUS_NO_MEMORY Failed to allocate provider binding context.
 * @retval STATUS_INVALID_PARAMETER One or more arguments are incorrect.
 */
static NTSTATUS
_net_ebpf_extension_program_info_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_program_info_client_t* program_info_client = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

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
        if (program_info_client) {
            ExFreePool(program_info_client);
        }
    }
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

/**
 * @brief Callback invoked when a Program Information NPI client detaches.
 *
 * @param[in] provider_binding_context Provider module's context for binding with the client.
 * @retval STATUS_SUCCESS The operation succeeded.
 * @retval STATUS_INVALID_PARAMETER One or more parameters are invalid.
 */
static NTSTATUS
_net_ebpf_extension_program_info_provider_detach_client(_In_ const void* provider_binding_context)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(provider_binding_context);

    return status;
}

static void
_net_ebpf_extension_program_info_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context)
{
    ExFreePool(provider_binding_context);
}

void
net_ebpf_extension_program_info_provider_unregister(
    _Frees_ptr_opt_ net_ebpf_extension_program_info_provider_t* provider_context)
{
    if (provider_context != NULL) {
        NTSTATUS status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
        if (status == STATUS_PENDING) {
            NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
        }
        ExFreePool(provider_context);
    }
}

NTSTATUS
net_ebpf_extension_program_info_provider_register(
    _In_ const net_ebpf_extension_program_info_provider_parameters_t* parameters,
    _Outptr_ net_ebpf_extension_program_info_provider_t** provider_context)
{
    net_ebpf_extension_program_info_provider_t* local_provider_context = NULL;
    NPI_PROVIDER_CHARACTERISTICS* characteristics;
    NTSTATUS status = STATUS_SUCCESS;

    NET_EBPF_EXT_LOG_ENTRY();

    local_provider_context = (net_ebpf_extension_program_info_provider_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_program_info_provider_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (local_provider_context == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }
    memset(local_provider_context, 0, sizeof(net_ebpf_extension_program_info_provider_t));

    characteristics = &local_provider_context->characteristics;
    characteristics->Length = sizeof(NPI_PROVIDER_CHARACTERISTICS);
    characteristics->ProviderAttachClient =
        (PNPI_PROVIDER_ATTACH_CLIENT_FN)_net_ebpf_extension_program_info_provider_attach_client;
    characteristics->ProviderDetachClient =
        (PNPI_PROVIDER_DETACH_CLIENT_FN)_net_ebpf_extension_program_info_provider_detach_client;
    characteristics->ProviderCleanupBindingContext = _net_ebpf_extension_program_info_provider_cleanup_binding_context;
    characteristics->ProviderRegistrationInstance.Size = sizeof(NPI_REGISTRATION_INSTANCE);
    characteristics->ProviderRegistrationInstance.NpiId = &EBPF_PROGRAM_INFO_EXTENSION_IID;
    characteristics->ProviderRegistrationInstance.NpiSpecificCharacteristics = parameters->provider_data;
    characteristics->ProviderRegistrationInstance.ModuleId = parameters->provider_module_id;

    status = NmrRegisterProvider(characteristics, local_provider_context, &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    *provider_context = local_provider_context;
    local_provider_context = NULL;

Exit:
    if (!NT_SUCCESS(status)) {
        net_ebpf_extension_program_info_provider_unregister(local_provider_context);
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}
