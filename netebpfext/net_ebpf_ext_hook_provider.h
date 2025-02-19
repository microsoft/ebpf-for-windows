// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_extension.h"
#include "framework.h"
#include "net_ebpf_ext.h"
#include "net_ebpf_ext_structs.h"

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

/**
 * @brief Block execution of the thread until all invocations are completed.
 *
 * @param[in, out] rundown Rundown object to wait for.
 *
 */
void
_ebpf_ext_wait_for_rundown(_Inout_ net_ebpf_ext_hook_rundown_t* rundown);