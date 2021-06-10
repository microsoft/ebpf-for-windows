// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <ntddk.h>

#include <ebpf_platform.h>

typedef enum _ebpf_ext_hook_execution
{
    EBPF_EXT_HOOK_EXECUTION_PASSIVE,
    EBPF_EXT_HOOK_EXECUTION_DISPATCH
} ebpf_ext_hook_execution_t;

typedef struct _ebpf_ext_attach_hook_provider_registration ebpf_ext_attach_hook_provider_registration_t;

/**
 * @brief Protect the registration from rundown.
 *
 * @param[in] registration Registration to protect.
 * @retval true - The caller should proceed.
 * @retval false - Rundown has occurred.
 */
bool
ebpf_ext_attach_enter_rundown(_In_ ebpf_ext_attach_hook_provider_registration_t* registration);

/**
 * @brief Unprotect the registration from rundown.
 *
 * @param registration
 */
void
ebpf_ext_attach_leave_rundown(_In_ ebpf_ext_attach_hook_provider_registration_t* registration);

/**
 * @brief Register as a attach type provider.
 *
 * @param[in] attach_type Attach type to register for.
 * @param[in,out] registration Registration to complete.
 * @param[in] execution_type Execution type for the hook (passive or dispatch).
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate resources for this
 * operation.
 */
ebpf_result_t
ebpf_ext_attach_register_provider(
    const ebpf_attach_type_t* attach_type,
    ebpf_ext_hook_execution_t execution_type,
    ebpf_ext_attach_hook_provider_registration_t** registration);

/**
 * @brief Unregister as an attach type provider.
 *
 * @param[in] registration Registration to cleanup.
 */
void
ebpf_ext_attach_unregister_provider(ebpf_ext_attach_hook_provider_registration_t* registration);

/**
 * @brief Invoke the eBPF program attached to this hook.
 *
 * @param[in] registration Registration that owns the hook.
 * @param[in] context Context to pass to eBPF program.
 * @param[out] result Return value from the eBPF program.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate resources for this
 * operation.
 */
ebpf_result_t
ebpf_ext_attach_invoke_hook(
    ebpf_ext_attach_hook_provider_registration_t* registration, void* context, uint32_t* result);