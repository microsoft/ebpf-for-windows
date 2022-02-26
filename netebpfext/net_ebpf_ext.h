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
#pragma warning(push)
#pragma warning(disable : 28253) // Inconsistent annotation for '_umul128'
#include <ntintsafe.h>
#pragma warning(pop)

#define INITGUID

#include <fwpmk.h>

#pragma warning(push)
#pragma warning(disable : 4201) // unnamed struct/union
#include <fwpsk.h>
#pragma warning(pop)

#include <guiddef.h>
#include <netiodef.h>
#include <ntddk.h>

#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_windows.h"

#include "net_ebpf_ext_hook_provider.h"
#include "net_ebpf_ext_prog_info_provider.h"
#include "net_ebpf_ext_program_info.h"

#define NET_EBPF_EXTENSION_POOL_TAG 'Nfbe'
#define NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

// Globals.
extern NDIS_HANDLE _net_ebpf_ext_nbl_pool_handle;
extern NDIS_HANDLE _net_ebpf_ext_ndis_handle;
extern HANDLE _net_ebpf_ext_l2_injection_handle;
extern DEVICE_OBJECT* _net_ebpf_ext_driver_device_object;

//
// Shared function prototypes.
//

/**
 * @brief Initialize global NDIS handles.
 *
 * @param[in] driver_object The driver object to associate the NDIS generic object handle with.
 * @retval STATUS_SUCCESS NDIS handles initialized successfully.
 * @retval STATUS_INSUFFICIENT_RESOURCES Failed to initialize NDIS handles due to insufficient resources.
 */
NTSTATUS
net_ebpf_ext_initialize_ndis_handles(_In_ const DRIVER_OBJECT* driver_object);

/**
 * @brief Uninitialize global NDIS handles.
 */
void
net_ebpf_ext_uninitialize_ndis_handles();

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