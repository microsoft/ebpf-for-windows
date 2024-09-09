// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_extension.h"
#include "framework.h"
#include "net_ebpf_ext.h"

typedef enum _net_ebpf_extension_hook_attach_capability
{
    ATTACH_CAPABILITY_MULTI_ATTACH_WITH_WILDCARD =
        0,                           ///< Multiple clients can attach to the hook, for each attach parameters.
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
 * @brief Callback function to create hook specific filter context. This callback is invoked when a hook NPI client
          is attempting to attach to the hook NPI provider.
 *
 * @param[in] attaching_client Pointer to context of the hook NPI client that is requesting to be attached.
 * @param[in] provider_context Pointer to the hook NPI provider context to which the client is being attached.
 * @param[out] filter_context Pointer to the filter context being created.
 *
 * @return EBPF_SUCCESS when operation succeeded, failure otherwise.
 */
typedef ebpf_result_t (*net_ebpf_extension_create_filter_context)(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context);

/**
 * @brief Callback function to delete hook specific filter context. This callback is invoked when a hook NPI client
          is detaching from the hook NPI provider.
 *
 * @param[in] filter_context Pointer to the filter context being deleted.
 */
typedef void (*net_ebpf_extension_delete_filter_context)(
    _In_opt_ _Frees_ptr_opt_ net_ebpf_extension_wfp_filter_context_t* filter_context);

/**
 * @brief Callback function to validate if the attach parameters (i.e., client data) is valid, and to get information
 *        if the attach parameter is a wildcard attach parameter.
 *
 * @param[in] client_data Pointer to the attach parameters (client data) that is being validated.
 * @param[out] is_wildcard Pointer to a boolean that will be set to true if the attach parameter is a wildcard attach
 *             parameter.
 *
 * @return EBPF_SUCCESS when the attach parameters are valid, failure otherwise.
 */
typedef ebpf_result_t (*net_ebpf_extension_validate_client_data)(
    _In_ const ebpf_extension_data_t* client_data, _Out_ bool* is_wildcard);

/**
 * @brief When hook provider supports multiple programs per hook, this callback function is invoked after
 * every program invocation to determine whether the next program in the list should be invoked.
 *
 * @param[in] program_context Pointer to context passed to the eBPF program.
 * @param[in] progrma_verdict Result returned by the eBPF program.
 *
 * @returns TRUE if the next program should be invoked, FALSE otherwise.
 */
typedef bool (*net_ebpf_extension_hook_process_verdict)(_Inout_ void* program_context, int program_verdict);

typedef struct _net_ebpf_extension_hook_provider_dispatch_table
{
    net_ebpf_extension_create_filter_context create_filter_context;
    net_ebpf_extension_delete_filter_context delete_filter_context;
    net_ebpf_extension_validate_client_data validate_client_data;
    net_ebpf_extension_hook_process_verdict process_verdict;
} net_ebpf_extension_hook_provider_dispatch_table_t;

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
 * @param[in] attach_capability Capability of the hook provider to attach clients.
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

/**
 * @brief Invoke all the eBPF programs attached to the specified filter context.
 *
 * @param[in] program_context Context to pass to eBPF program.
 * @param[in] filter_context Filter context to invoke the programs from.
 * @param[out] result Return value from the eBPF programs.
 *
 * @retval ebpf_result_t Status of the program invocation.
 */
ebpf_result_t
net_ebpf_extension_hook_invoke_programs(
    _Inout_ void* program_context,
    _In_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _Out_ uint32_t* result);

/**
 * @brief Expand stack and invoke all the eBPF programs attached to the specified filter context.
 *
 * @param[in,out] program_context Context to pass to eBPF program.
 * @param[in,out] filter_context Filter context to invoke the programs from.
 * @param[out] result Return value from the eBPF programs.
 *
 * @return Status of the program invocation.
 */
ebpf_result_t
net_ebpf_extension_hook_expand_stack_and_invoke_programs(
    _Inout_ void* program_context,
    _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _Out_ uint32_t* result);

/**
 * @brief Get attach capability for the hook provider.
 *
 * @param provider_context Pointer to the hook provider context.
 *
 * @return Attach capability for the hook provider.
 */
net_ebpf_extension_hook_attach_capability_t
net_ebpf_extension_hook_provider_get_attach_capability(_In_ const net_ebpf_extension_hook_provider_t* provider_context);