// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Header file for structures/prototypes of the driver.
 */

#pragma once

#include <ntddk.h>
#include "ebpf_platform.h"

typedef struct _test_program_context test_program_context_t;

/**
 * @brief Register program information NPI provider.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
sample_ebpf_extension_program_info_provider_register();

/**
 * @brief Unregister program information NPI provider.
 *
 */
void
sample_ebpf_extension_program_info_provider_unregister();

/**
 * @brief Register hook NPI provider.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
sample_ebpf_extension_hook_provider_register();

/**
 * @brief Unregister test hook provider.
 *
 */
void
sample_ebpf_extension_hook_provider_unregister();

/**
 * @brief Invoke eBPF program attached to a hook provider instance.
 *
 * @param[in] context Pointer to eBPF program context.
 * @param[out] result Result returned by eBPF program at the end of execution.
 *
 * @retval EBPF_SUCCESS Operation succeeded.
 * @retval EBPF_OPERATION_NOT_SUPPORTED Operation not supported.
 */
ebpf_result_t
sample_ebpf_extension_invoke_program(_In_ const test_program_context_t* context, _Out_ uint32_t* result);