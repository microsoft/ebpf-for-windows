// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "net_ebpf_ext.h"

typedef struct _net_ebpf_extension_program_info_provider net_ebpf_extension_program_info_provider_t;

/**
 * @brief Register the program information NPI provider.
 *
 * @param[in] provider_characteristics Pointer to the NPI provider characteristics struct.
 * @param[in,out] provider_context Pointer to the provider context being registered.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
net_ebpf_extension_program_info_provider_register(
    _In_ const NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    _Outptr_ net_ebpf_extension_program_info_provider_t** provider_context);

/**
 * @brief Unregister the program information NPI provider.
 *
 * @param[in] provider_context Pointer to the provider context being un-registered.
 */
void
net_ebpf_extension_program_info_provider_unregister(
    _Frees_ptr_opt_ net_ebpf_extension_program_info_provider_t* provider_context);

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
NTSTATUS
net_ebpf_extension_program_info_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch);

/**
 * @brief Callback invoked when a Program Information NPI client detaches.
 *
 * @param[in] provider_binding_context Provider module's context for binding with the client.
 * @retval STATUS_SUCCESS The operation succeeded.
 * @retval STATUS_INVALID_PARAMETER One or more parameters are invalid.
 */
NTSTATUS
net_ebpf_extension_program_info_provider_detach_client(_Frees_ptr_opt_ void* provider_binding_context);