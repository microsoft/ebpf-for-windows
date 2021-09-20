// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Header file for structures/prototypes of the driver.
 */

#pragma once

#include <ntddk.h>
#include "ebpf_platform.h"
#include "sample_ext_ioctls.h"

typedef struct _sample_program_context sample_program_context_t;

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
sample_ebpf_extension_invoke_program(_In_ const sample_program_context_t* context, _Out_ uint32_t* result);

/**
 * @brief Invoke eBPF program attached to a hook provider instance and measure the execution time.
 *
 * @param[in] request Request containing the parameters of the test.
 * @param[in] request_length Length of the request buffer.
 * @param[out] reply Reply containing the results of the test.
 *
 * @retval EBPF_SUCCESS Operation succeeded.
 * @retval EBPF_OPERATION_NOT_SUPPORTED Operation not supported.
 */
ebpf_result_t
sample_ebpf_extension_profile_program(
    _In_ sample_ebpf_ext_profile_request_t* request,
    size_t request_length,
    _Inout_ sample_ebpf_ext_profile_reply_t* reply);
