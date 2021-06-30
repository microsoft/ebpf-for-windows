// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/*++

Abstract:

   Header file for structures/prototypes of the driver.


Environment:

    Kernel mode

--*/

#pragma once

#include <ntddk.h>
#include "ebpf_platform.h"

typedef struct _test_program_context test_program_context_t;

/**
 * @brief Register program information providers with eBPF core.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
test_ebpf_extension_program_info_provider_register();

/**
 * @brief Unregister program information providers from eBPF core.
 *
 */
void
test_ebpf_extension_program_info_provider_unregister();

/**
 * @brief Register hook providers with eBPF core.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
test_ebpf_extension_hook_provider_register();

/**
 * @brief Unregister hook providers from eBPF core.
 *
 */
void
test_ebpf_extension_hook_provider_unregister();

/**
 * @brief Invoke eBPF program attached to a hook provider instance.
 *
 * @param context Pointer to eBPF program context.
 * @param result Result returned by eBPF program at the end of execution.
 *
 * @retval EBPF_SUCCESS Operation succeeded.
 * @retval EBPF_OPERATION_NOT_SUPPORTED Operation not supported.
 */
ebpf_result_t
test_ebpf_extension_invoke_program(_In_ test_program_context_t* context, _Out_ uint32_t* result);