// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "net_ebpf_ext.h"

typedef struct _net_ebpf_extension_program_info_provider net_ebpf_extension_program_info_provider_t;
typedef struct _net_ebpf_extension_program_info_client net_ebpf_extension_program_info_client_t;

/**
 * @brief Pointer to function to get the context for the current invocation of the eBPF program.
 * This is the only function in the client's dispatch table.
 */
typedef ebpf_result_t (*ebpf_get_program_context_t)(_Outptr_ void** context);

/**
 * @brief Data structure for program info NPI provider registration parameters.
 */
typedef struct _net_ebpf_extension_program_info_provider_parameters
{
    const NPI_MODULEID* provider_module_id;     ///< NPI provider module ID.
    const ebpf_extension_data_t* provider_data; ///< Program info NPI provider data (contains ebpf_program_data_t).
} net_ebpf_extension_program_info_provider_parameters_t;

/**
 * @brief Unregister the program information NPI provider.
 *
 * @param[in] provider_context Pointer to the provider context being un-registered.
 */
void
net_ebpf_extension_program_info_provider_unregister(
    _Frees_ptr_opt_ net_ebpf_extension_program_info_provider_t* provider_context);

/**
 * @brief This callback function should be implemented by program info provider modules. This callback is invoked when
 * a program info NPI client is attempting to attach to the program info NPI provider.
 * @param[in] attaching_client Pointer to context of the hook NPI client that is requesting to be attached.
 * @param[in] provider_context Pointer to the hook NPI provider context to which the client is being attached.
 *
 * @retval EBPF_SUCCESS The operation succeeded.
 * @retval EBPF_ACCESS_DENIED Request to attach client is denied by the provider.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 */
typedef ebpf_result_t (*net_ebpf_extension_program_info_on_client_attach)(
    _In_ const net_ebpf_extension_program_info_client_t* attaching_client,
    _In_ const net_ebpf_extension_program_info_provider_t* provider_context);

/**
 * @brief This callback function should be implemented by program info provider modules. This callback is invoked when
 * a program info NPI client is attempting to detach from the program info NPI provider.
 * @param[in] detaching_client Pointer to context of the hook NPI client that is requesting to be detached.
 *
 */
typedef void (*net_ebpf_extension_program_info_on_client_detach)(
    _In_ const net_ebpf_extension_program_info_client_t* detaching_client);

/**
 * @brief Register the program information NPI provider.
 *
 * @param[in] provider_characteristics Pointer to the NPI provider characteristics struct.
 * @param[in] attach_callback Optionally, pointer to callback function to be invoked when a client attaches.
 * @param[in] detach_callback Optionally, pointer to callback function to be invoked when a client detaches.
 * @param[in, out] provider_context Pointer to the provider context being registered.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_NO_MEMORY Not enough memory to allocate resources.
 */
NTSTATUS
net_ebpf_extension_program_info_provider_register(
    _In_ const net_ebpf_extension_program_info_provider_parameters_t* parameters,
    _In_opt_ net_ebpf_extension_program_info_on_client_attach attach_callback,
    _In_opt_ net_ebpf_extension_program_info_on_client_detach detach_callback,
    _Outptr_ net_ebpf_extension_program_info_provider_t** provider_context);

/**
 * @brief Get the ebpf_get_program_context_t function pointer.
 *
 * @param[in] program_info_client Pointer to program info NPI client.
 *
 * @returns ebpf_get_program_context_t function pointer.
 */
const ebpf_get_program_context_t
net_ebpf_extension_get_program_context_function(
    _In_ const net_ebpf_extension_program_info_client_t* program_info_client);
