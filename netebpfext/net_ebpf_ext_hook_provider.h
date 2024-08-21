// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_extension.h"
#include "framework.h"
#include "net_ebpf_ext.h"

typedef enum _net_ebpf_extension_hook_attach_capability
{
    ATTACH_CAPABILITY_MULTI_ATTACH = 0, ///< Multiple clients can attach to the hook, for each attach parameters.
    ATTACH_CAPABILITY_SINGLE_ATTACH, ///< Only one client can attach to the hook, irrespective of the attach parameters.
    ATTACH_CAPABILITY_SINGLE_ATTACH_PER_HOOK, ///< One client can attach to the hook for each attach parameter, but with
                                              ///< wildcard attach parameter, only one client can attach.
} net_ebpf_extension_hook_attach_capability_t;

/**
 *  @brief This is the per client binding context for the eBPF Hook
 *         NPI provider.
 */
typedef struct _net_ebpf_extension_hook_client net_ebpf_extension_hook_client_t;

/**
 *  @brief This is the per filter context for the eBPF Hook
 *         NPI provider.
 */
typedef struct _net_ebpf_extension_wfp_filter_context net_ebpf_extension_wfp_filter_context_t;

/**
 *  @brief This is the provider context of eBPF Hook NPI provider.
 */
typedef struct _net_ebpf_extension_hook_provider net_ebpf_extension_hook_provider_t;

// /**
//  * @brief Attempt to acquire rundown.
//  *
//  * @param[in, out] hook_client Pointer to attached hook NPI client.
//  *
//  * @retval TRUE Rundown was acquired successfully.
//  * @retval False Rundown acquisition failed.
//  */
// _Must_inspect_result_ bool
// net_ebpf_extension_hook_client_enter_rundown(_Inout_ net_ebpf_extension_hook_client_t* hook_client);

// /**
//  * @brief Release rundown.
//  *
//  * @param[in, out] hook_client Pointer to attached hook NPI client.
//  */
// void
// net_ebpf_extension_hook_client_leave_rundown(_Inout_ net_ebpf_extension_hook_client_t* hook_client);

void
net_ebpf_extension_hook_provider_leave_rundown(_Inout_ net_ebpf_extension_hook_provider_t* provider_context);

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
 * @brief Get the hook-specific custom data from the provider.
 *
 * @param[in] provider_context Pointer to hook NPI provider.
 *
 * @returns Pointer to the hook-specific custom data from the provider.
 */
const void*
net_ebpf_extension_hook_provider_get_custom_data(_In_ const net_ebpf_extension_hook_provider_t* provider_context);

/**
 * @brief Unregister the hook NPI provider.
 *
 * @param[in] provider_context Pointer to the provider context being un-registered.
 */
void
net_ebpf_extension_hook_provider_unregister(
    _In_opt_ _Frees_ptr_opt_ net_ebpf_extension_hook_provider_t* provider_context);

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

typedef ebpf_result_t (*net_ebpf_extension_create_filter_context)(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context);

typedef void (*net_ebpf_extension_delete_filter_context)(
    _In_opt_ _Frees_ptr_opt_ net_ebpf_extension_wfp_filter_context_t* filter_context);

// typedef bool (*net_ebpf_extension_can_append_client)(
//     _In_ const const ebpf_extension_data_t* client_data,
//     _In_ const net_ebpf_extension_wfp_filter_context_t* filter_context);

typedef ebpf_result_t (*net_ebpf_extension_validate_client_data)(
    _In_ const ebpf_extension_data_t* client_data, _Out_ bool* is_wildcard);

typedef struct _net_ebpf_extension_hook_provider_dispatch_table
{
    net_ebpf_extension_create_filter_context create_filter_context;
    net_ebpf_extension_delete_filter_context delete_filter_context;
    // net_ebpf_extension_can_append_client can_append_client;
    net_ebpf_extension_validate_client_data validate_client_data;
} net_ebpf_extension_hook_provider_dispatch_table_t;

// /**
//  * @brief This callback function should be implemented by hook modules. This callback is invoked when a hook NPI
//  client
//  * is attempting to detach from the hook NPI provider.
//  * @param detaching_client Pointer to context of the hook NPI client that is requesting to be detached.
//  */
// typedef void (*net_ebpf_extension_hook_on_client_detach)(_In_ const net_ebpf_extension_hook_client_t*
// detaching_client);

/**
 * @brief Data structure for hook NPI provider registration parameters.
 */
typedef struct _net_ebpf_extension_hook_provider_parameters
{
    const NPI_MODULEID* provider_module_id;           ///< NPI provider module ID.
    const ebpf_attach_provider_data_t* provider_data; ///< Hook provider data (contains supported program types).
} net_ebpf_extension_hook_provider_parameters_t;

/**
 * @brief Register the hook NPI provider.
 *
 * @param[in] parameters Pointer to the NPI provider characteristics struct.
 * @param[in] dispatch Pointer to dispatch table.
 * @param[in] custom_data (Optional) Opaque pointer to hook-specific custom data.
 * @param[in, out] provider_context Pointer to the provider context being registered.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_NO_MEMORY Not enough memory to allocate resources.
 */
NTSTATUS
net_ebpf_extension_hook_provider_register(
    _In_ const net_ebpf_extension_hook_provider_parameters_t* parameters,
    _In_ const net_ebpf_extension_hook_provider_dispatch_table_t* dispatch,
    net_ebpf_extension_hook_attach_capability_t attach_capability,
    _In_opt_ const void* custom_data,
    _Outptr_ net_ebpf_extension_hook_provider_t** provider_context);

// /**
//  * @brief Invoke the eBPF program attached to this hook. This must be called
//  * inside a net_ebpf_extension_hook_client_enter_rundown/net_ebpf_extension_hook_client_leave_rundown block.
//  *
//  * @param[in] client Pointer to Hook NPI Client (a.k.a. eBPF Link object).
//  * @param[in] context Context to pass to eBPF program.
//  * @param[out] result Return value from the eBPF program.
//  * @retval EBPF_SUCCESS The operation was successful.
//  * @retval EBPF_NO_MEMORY Unable to allocate resources for this
//  * operation.
//  */
// _Must_inspect_result_ ebpf_result_t
// _net_ebpf_extension_hook_invoke_program(
//     _In_ const net_ebpf_extension_hook_client_t* client, _Inout_ void* context, _Out_ uint32_t* result);

/**
 * @brief When hook provider supports multiple programs per hook, this callback function is invoked after
 * every program invocation to determine whether we should continue invoking next program in the list.
 * @param[in] progrma_verdict Pointer to context of the hook NPI client that is requesting to be detached.
 *
 * @returns TRUE if the next program should be invoked, FALSE otherwise.
 */
typedef bool (*net_ebpf_extension_hook_process_verdict)(int program_verdict);

// /**
//  * @brief Return client attached to the hook NPI provider.
//  * @param[in, out] provider_context Provider module's context.
//  * @returns Attached client.
//  * (Note: this is a temporary helper routine that will be re-written when multiple attached clients are supported as
//  fix
//  * to #754)
//  */
// net_ebpf_extension_hook_client_t*
// net_ebpf_extension_hook_get_attached_client(_Inout_ net_ebpf_extension_hook_provider_t* provider_context);

// /**
//  * @brief Utility function called from net_ebpf_extension_hook_on_client_attach callback of hook providers, that
//  * determines if the attach parameter provided by an attaching client is compatible with the existing clients.
//  * @param[in] attach_parameter_size The expected length (in bytes) of attach parameter for this type of hook.
//  * @param[in] attach_parameter The attach parameter supplied by the client requesting to be attached.
//  * @param[in] wild_card_attach_parameter Pointer to wild card parameter for this type of hook.
//  * @param[in, out] provider_context Provider module's context.
//  * @retval EBPF_SUCCESS The operation succeeded.
//  * @retval EBPF_ACCESS_DENIED Request to attach client is denied by the provider.
//  * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
//  */
// _Must_inspect_result_ ebpf_result_t
// net_ebpf_extension_hook_check_attach_parameter(
//     size_t attach_parameter_size,
//     _In_reads_(attach_parameter_size) const void* attach_parameter,
//     _In_reads_(attach_parameter_size) const void* wild_card_attach_parameter,
//     _Inout_ net_ebpf_extension_hook_provider_t* provider_context);

net_ebpf_extension_hook_client_t*
net_ebpf_extension_get_matching_client(
    size_t attach_parameter_size,
    _In_reads_(attach_parameter_size) const void* attach_parameter,
    _In_reads_(attach_parameter_size) const void* wild_card_attach_parameter,
    _In_ net_ebpf_extension_hook_provider_t* provider_context);

// void
// net_ebpf_extension_hook_client_insert(
//     _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
//     _Inout_ net_ebpf_extension_hook_client_t* client_context);

// void
// net_ebpf_extension_hook_client_remove(
//     _Inout_ void* filter_context, _In_ net_ebpf_extension_hook_client_t* client_context);

ebpf_result_t
net_ebpf_extension_hook_invoke_programs(
    _Inout_ void* program_context,
    _In_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _In_opt_ const net_ebpf_extension_hook_process_verdict process_callback,
    _Out_ uint32_t* result);

// /**
//  * @brief Acquire the spin lock (shared) for the hook provider.
//  *
//  * @param provider_context Pointer to the provider context.
//  * @return The old IRQL.
//  */
// _Acquires_shared_lock_(provider_context->spin_lock) _IRQL_requires_max_(DISPATCH_LEVEL) KIRQL
//     net_ebpf_extension_hook_acquire_spin_lock_shared(_Inout_ net_ebpf_extension_hook_provider_t* provider_context);

// /**
//  * @brief Release the spin lock (shared) for the hook provider.
//  *
//  * @param provider_context Pointer to the provider context.
//  * @param old_irql Old IRQL.
//  */
// _Releases_shared_lock_(provider_context->spin_lock)
//     _IRQL_requires_(DISPATCH_LEVEL) void net_ebpf_extension_hook_release_spin_lock_shared(
//         _Inout_ net_ebpf_extension_hook_provider_t* provider_context, KIRQL old_irql);