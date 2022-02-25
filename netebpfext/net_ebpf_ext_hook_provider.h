// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "net_ebpf_ext.h"

typedef enum _net_ebpf_extension_hook_execution
{
    EXECUTION_PASSIVE,
    EXECUTION_DISPATCH
} net_ebpf_extension_hook_execution_t;

/**
 *  @brief This is the per client binding context for the eBPF Hook
 *         NPI provider.
 */
typedef struct _net_ebpf_extension_hook_client net_ebpf_extension_hook_client_t;

/**
 * @brief Attempt to acquire rundown.
 *
 * @param[in, out] hook_client Pointer to attached hook NPI client.
 * @param[in] execution_type Execution type for the hook (passive or dispatch).
 *
 * @retval true The caller should proceed.
 * @retval false Rundown has occurred.
 */
_Acquires_lock_(hook_client) bool net_ebpf_extension_attach_enter_rundown(
    _Inout_ net_ebpf_extension_hook_client_t* hook_client, net_ebpf_extension_hook_execution_t execution_type);

/**
 * @brief Release rundown.
 *
 * @param[in, out] hook_client Pointer to attached hook NPI client.
 * @param[in] execution_type Execution type for the hook (passive or dispatch).

 */
_Releases_lock_(hook_client) void net_ebpf_extension_attach_leave_rundown(
    _Inout_ net_ebpf_extension_hook_client_t* hook_client, net_ebpf_extension_hook_execution_t execution_type);

/**
 * @brief Get the hook-specific data for a given client registration.
 *
 * @param[in] hook_client Pointer to attached hook NPI client.
 *
 * @returns Hook-specific client data.
 */
const ebpf_extension_data_t*
net_ebpf_extension_get_client_data(_In_ const net_ebpf_extension_hook_client_t* hook_client);

/**
 *  @brief This is the provider context of eBPF Hook NPI provider.
 */
typedef struct _net_ebpf_extension_hook_provider net_ebpf_extension_hook_provider_t;

/**
 * @brief Unregister the hook NPI provider.
 *
 * @param[in] provider_context Pointer to the provider context being un-registered.
 */
void
net_ebpf_extension_hook_provider_unregister(_Frees_ptr_opt_ net_ebpf_extension_hook_provider_t* provider_context);

/**
 * @brief Register the hook NPI provider.
 *
 * @param[in] provider_characteristics Pointer to the NPI provider characteristics struct.
 * @param[in] execution_type Execution type for the hook (passive or dispatch).
 * @param[in,out] provider_context Pointer to the provider context being registered.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
net_ebpf_extension_hook_provider_register(
    _In_ const NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    net_ebpf_extension_hook_execution_t execution_type,
    _Outptr_ net_ebpf_extension_hook_provider_t** provider_context);

/**
 * @brief Callback invoked when an eBPF hook NPI client (a.k.a eBPF link object) attaches.
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

NTSTATUS
net_ebpf_extension_hook_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch);

/**
 * @brief Callback invoked when a hook NPI client (a.k.a eBPF link object) detaches.
 *
 * @param[in] provider_binding_context Provider module's context for binding with the client.
 * @retval STATUS_SUCCESS The operation succeeded.
 * @retval STATUS_INVALID_PARAMETER One or more parameters are invalid.
 */
NTSTATUS
net_ebpf_extension_hook_provider_detach_client(_In_ void* provider_binding_context);

/**
 * @brief Invoke the eBPF program attached to this hook. This must be called
 * inside a net_ebpf_extension_attach_enter_rundown/net_ebpf_extension_attach_leave_rundown block.
 *
 * @param[in] client Pointer to Hook NPI Client (a.k.a. eBPF Link object).
 * @param[in] context Context to pass to eBPF program.
 * @param[out] result Return value from the eBPF program.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate resources for this
 * operation.
 */
ebpf_result_t
net_ebpf_extension_hook_invoke_program(
    _In_ const net_ebpf_extension_hook_client_t* client, _In_ void* context, _Out_ uint32_t* result);

/**
 * @brief Return client attached to the hook NPI provider.
 * @param[in] provider_context Provider module's context.
 * @returns Attached client.
 * (Note: this is a temporary helper routine that will be re-written when multiple attached clients are supported as fix
 * to #754)
 */
net_ebpf_extension_hook_client_t*
net_ebpf_extension_get_attached_client(_In_ const net_ebpf_extension_hook_provider_t* provider_context);