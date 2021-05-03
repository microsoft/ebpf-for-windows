/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

/*++

Abstract:

   Header file for structures/prototypes of the driver.


Environment:

    Kernel mode

--*/

#pragma once

#include <ntddk.h>

//
// Shared function prototypes
//

/**
 * @brief Register for the WFP callouts used to power hooks.
 *
 * @param[in] device_object Device object used by this driver.
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval FWP_E_* A Windows Filtering Platform (WFP) specific error.
 */
NTSTATUS
ebpf_hook_register_callouts(_Inout_ void* device_object);

/**
 * @brief Unregister the WFP callouts.
 *
 */
void
ebpf_hook_unregister_callouts(void);

/**
 * @brief Register hook providers with eBPF core.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
ebpf_hook_register_providers();

/**
 * @brief Unregister hook providers from eBPF core.
 *
 */
void
ebpf_hook_unregister_providers();

/**
 * @brief Register program information providers with eBPF core.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
ebpf_program_information_provider_register();

/**
 * @brief Unregister program information providers from eBPF core.
 *
 */
void
ebpf_program_information_provider_unregister();