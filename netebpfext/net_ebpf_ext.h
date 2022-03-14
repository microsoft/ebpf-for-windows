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
#include <netioapi.h>
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

typedef struct _net_ebpf_extension_wfp_filter_parameters
{
    const GUID* layer_guid;     ///< GUID of WFP layer to which this filter is associated.
    const GUID* callout_guid;   ///< GUID of WFP callout to which this filter is associated.
    const wchar_t* name;        ///< Display name of filter.
    const wchar_t* description; ///< Description of filter.
} net_ebpf_extension_wfp_filter_parameters_t;

/**
 * @brief Add WFP filters with specified conditions at specified layers.
 *
 * @param[in]  filter_count Count of filters to be added.
 * @param[in]  filter Parameters Filter parameters.
 * @param[in]  condition_count Count of filter conditions.
 * @param[in]  conditions Common filter conditions to be applied to each filter.
 * @param[in]  raw_context Caller supplied context to be associated with the WFP filter.
 * @param[out] filter_ids Output buffer where the added filter IDs are stored.
 *
 * @retval EBPF_SUCCESS The operation completed successfully.
 * @retval EBPF_INVALID_ARGUMENT One or more arguments are invalid.
 */
ebpf_result_t
net_ebpf_extension_add_wfp_filters(
    uint32_t filter_count,
    _In_count_(filter_count) const net_ebpf_extension_wfp_filter_parameters_t* parameters,
    uint32_t condition_count,
    _In_opt_count_(condition_count) const FWPM_FILTER_CONDITION* conditions,
    _In_ const void* raw_context,
    _Out_writes_(filter_count) uint64_t* filter_ids);

/**
 * @brief Deletes WFP filters with specified filter IDs.
 *
 * @param[in]  filter_count Count of filters to be added.
 * @param[in]  filter_ids ID of the filter being deleted.
 */
void
net_ebpf_extension_delete_wfp_filters(uint32_t filter_count, _In_count_(filter_count) uint64_t* filter_ids);

// eBPF WFP Sublayer GUID.
// 7c7b3fb9-3331-436a-98e1-b901df457fff
DEFINE_GUID(EBPF_SUBLAYER, 0x7c7b3fb9, 0x3331, 0x436a, 0x98, 0xe1, 0xb9, 0x01, 0xdf, 0x45, 0x7f, 0xff);

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
net_ebpf_extension_initialize_wfp_components(_Inout_ void* device_object);

/**
 * @brief Unregister the WFP callouts.
 *
 */
void
net_ebpf_extension_uninitialize_wfp_components(void);

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