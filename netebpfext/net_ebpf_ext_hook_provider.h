// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "net_ebpf_ext.h"

/**
 *  @brief This is the per client binding context for the eBPF Hook
 *         NPI provider.
 */
typedef struct _net_ebpf_extension_hook_client net_ebpf_extension_hook_client_t;

/**
 * @brief Attempt to acquire rundown.
 *
 * @param[in, out] hook_client Pointer to attached hook NPI client.
 *
 * @retval true The caller should proceed.
 * @retval false Rundown has occurred.
 */
bool
net_ebpf_extension_hook_client_enter_rundown(_Inout_ net_ebpf_extension_hook_client_t* hook_client);

/**
 * @brief Release rundown.
 *
 * @param[in, out] hook_client Pointer to attached hook NPI client.

 */
void
net_ebpf_extension_hook_client_leave_rundown(_Inout_ net_ebpf_extension_hook_client_t* hook_client);

/**
 * @brief Get the attach parameters for the input client.
 *
 * @param[in] hook_client Pointer to attached hook NPI client.
 *
 * @returns Attach parameters.
 */
const ebpf_extension_data_t*
net_ebpf_extension_hook_client_get_client_data(_In_ const net_ebpf_extension_hook_client_t* hook_client);

/**
 * @brief Set the hook-specific provider data for the attached client.
 *
 * @param[in] hook_client Pointer to attached hook NPI client.
 * @param[in] data hook-specific provider data.
 *
 */
void
net_ebpf_extension_hook_client_set_provider_data(_In_ net_ebpf_extension_hook_client_t* hook_client, const void* data);

/**
 * @brief Get the hook-specific provider data for the attached client.
 *
 * @param[in] hook_client Pointer to attached hook NPI client.
 *
 * @returns Pointer to hook-specific provider data for the attached client.
 */
const void*
net_ebpf_extension_hook_client_get_provider_data(_In_ const net_ebpf_extension_hook_client_t* hook_client);

/**
 *  @brief This is the provider context of eBPF Hook NPI provider.
 */
typedef struct _net_ebpf_extension_hook_provider net_ebpf_extension_hook_provider_t;

/**
 * @brief Get the hook-specific custom data from the provider.
 *
 * @param[in] provider_context Pointer to hook NPI provider.
 *
 * @returns Pointer to the hook-specific custom data from the provider.
 *
 */
const void*
net_ebpf_extension_hook_provider_get_custom_data(_In_ const net_ebpf_extension_hook_provider_t* provider_context);

/**
 * @brief Unregister the hook NPI provider.
 *
 * @param[in] provider_context Pointer to the provider context being un-registered.
 */
void
net_ebpf_extension_hook_provider_unregister(_Frees_ptr_opt_ net_ebpf_extension_hook_provider_t* provider_context);

/**
 * @brief This callback function should be implemented by hook modules. This callback is invoked when a hook NPI client
 * is attempting to attach to the hook NPI provider. The hook NPI client is allowed to attach only if the API returns
 * success.
 * @param attaching_client Pointer to context of the hook NPI client that is requesting to be attached.
 * @param provider_context Pointer to the hook NPI provider context to which the client is being attached.
 *
 * @retval EBPF_SUCCESS The operation succeeded.
 * @retval EBPF_ACCESS_DENIED Request to attach client is denied by the provider.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 */
typedef ebpf_result_t (*net_ebpf_extension_hook_on_client_attach)(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context);

/**
 * @brief This callback function should be implemented by hook modules. This callback is invoked when a hook NPI client
 * is attempting to detach from the hook NPI provider.
 * @param detaching_client Pointer to context of the hook NPI client that is requesting to be detached.
 *
 */
typedef void (*net_ebpf_extension_hook_on_client_detach)(_In_ const net_ebpf_extension_hook_client_t* detaching_client);

/**
 * @brief Data structure for hook NPI provider registration parameters.
 */
typedef struct _net_ebpf_extension_hook_provider_parameters
{
    const NPI_MODULEID* provider_module_id;     ///< NPI provider module ID.
    const ebpf_extension_data_t* provider_data; ///< Hook provider data (contains supported program types).
} net_ebpf_extension_hook_provider_parameters_t;

/**
 * @brief Register the hook NPI provider.
 *
 * @param[in] parameters Pointer to the NPI provider characteristics struct.
 * @param[in] attach_callback Pointer to callback function to be invoked when a client attaches.
 * @param[in] detach_callback Pointer to callback function to be invoked when a client detaches.
 * @param[in] custom_data (Optional) Opaque pointer to hook-specific custom data.
 * @param[in,out] provider_context Pointer to the provider context being registered.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_NO_MEMORY Not enough memory to allocate resources.
 */
NTSTATUS
net_ebpf_extension_hook_provider_register(
    _In_ const net_ebpf_extension_hook_provider_parameters_t* parameters,
    _In_ net_ebpf_extension_hook_on_client_attach attach_callback,
    _In_ net_ebpf_extension_hook_on_client_detach detach_callback,
    _In_opt_ const void* custom_data,
    _Outptr_ net_ebpf_extension_hook_provider_t** provider_context);

/**
 * @brief Invoke the eBPF program attached to this hook. This must be called
 * inside a net_ebpf_extension_hook_client_enter_rundown/net_ebpf_extension_hook_client_leave_rundown block.
 *
 * @param[in] client Pointer to Hook NPI Client (a.k.a. eBPF Link object).
 * @param[in] context Context to pass to eBPF program.
 * @param[out] result Return value from the eBPF program.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate resources for this
 * operation.
 */
_Must_inspect_result_ ebpf_result_t
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
net_ebpf_extension_hook_get_attached_client(_In_ net_ebpf_extension_hook_provider_t* provider_context);

/**
 * @brief Return the next client attached to the hook NPI provider.
 * @param[in] provider_context Provider module's context.
 * @param[in] client_context Caller supplied pointer to client_context. May be NULL.
 * @returns The next client after the one passed in client_context parameter. If the input client context is NULL, then
 * the first attached client context (if any) is returned.
 */
net_ebpf_extension_hook_client_t*
net_ebpf_extension_hook_get_next_attached_client(
    _In_ net_ebpf_extension_hook_provider_t* provider_context,
    _In_opt_ const net_ebpf_extension_hook_client_t* client_context);

/**
 * @brief Utility function called from net_ebpf_extension_hook_on_client_attach callback of hook providers, that
 * determines if the attach parameter provided by an attaching client is compatible with the existing clients.
 * @param[in] attach_parameter_size The expected length (in bytes) of attach parameter for this type of hook.
 * @param[in] attach_parameter The attach parameter supplied by the client requesting to be attached.
 * @param[in] wild_card_attach_parameter Pointer to wild card parameter for this type of hook.
 * @param[in] provider_context Provider module's context.
 * @retval EBPF_SUCCESS The operation succeeded.
 * @retval EBPF_ACCESS_DENIED Request to attach client is denied by the provider.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 */
_Must_inspect_result_ ebpf_result_t
net_ebpf_extension_hook_check_attach_parameter(
    size_t attach_parameter_size,
    _In_reads_(attach_parameter_size) const void* attach_parameter,
    _In_reads_(attach_parameter_size) const void* wild_card_attach_parameter,
    _In_ net_ebpf_extension_hook_provider_t* provider_context);
