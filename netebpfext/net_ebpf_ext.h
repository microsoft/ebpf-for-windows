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

#define INITGUID

#include <fwpmk.h>

#pragma warning(push)
#pragma warning(disable : 4201) // unnamed struct/union
#include <fwpsk.h>
#pragma warning(pop)

#include <guiddef.h>
#include <netiodef.h>
#include <ntddk.h>

#include "ebpf_ext_attach_provider.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_windows.h"

#define NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

//
// Shared function prototypes.
//

/**
 * @brief Register for the WFP callouts used to power hooks.
 *
 * @param[in] device_object Device object used by this driver.
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval FWP_E_* A Windows Filtering Platform (WFP) specific error.
 */
NTSTATUS
net_ebpf_ext_register_callouts(_Inout_ void* device_object);

/**
 * @brief Unregister the WFP callouts.
 *
 */
void
net_ebpf_ext_unregister_callouts(void);

/**
 * @brief Register network extension NPI providers with eBPF core.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
net_ebpf_ext_register_providers();

/**
 * @brief Unregister network extension NPI providers from eBPF core.
 *
 */
void
net_ebpf_ext_unregister_providers();