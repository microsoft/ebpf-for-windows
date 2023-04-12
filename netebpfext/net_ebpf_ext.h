// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief Header file for structures/prototypes of the driver.
 */

#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_program_types.h"
#include "ebpf_windows.h"
#include "net_ebpf_ext_hook_provider.h"
#include "net_ebpf_ext_prog_info_provider.h"
#include "net_ebpf_ext_program_info.h"
#include "net_ebpf_ext_tracelog.h"
#include "netebpfext_platform.h"

#include <guiddef.h>
#include <netioapi.h>
#include <netiodef.h>

#define NET_EBPF_EXTENSION_POOL_TAG 'Nfbe'
#define NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

CONST IN6_ADDR DECLSPEC_SELECTANY in6addr_v4mappedprefix = IN6ADDR_V4MAPPEDPREFIX_INIT;

#define htonl(x) _byteswap_ulong(x)
#define htons(x) _byteswap_ushort(x)
#define ntohl(x) _byteswap_ulong(x)
#define ntohs(x) _byteswap_ushort(x)
struct _net_ebpf_extension_hook_client;

typedef struct _wfp_ale_layer_fields
{
    uint16_t local_ip_address_field;
    uint16_t local_port_field;
    uint16_t remote_ip_address_field;
    uint16_t remote_port_field;
    uint16_t protocol_field;
    uint32_t direction_field;
    uint16_t compartment_id_field;
    uint16_t interface_luid_field;
    uint16_t user_id_field;
    uint16_t flags_field;
} wfp_ale_layer_fields_t;

typedef struct _net_ebpf_extension_wfp_filter_parameters
{
    const GUID* layer_guid;     ///< GUID of WFP layer to which this filter is associated.
    const GUID* sublayer_guid;  ///< GUID of the WFP sublayer to which this filter is associated.
    const GUID* callout_guid;   ///< GUID of WFP callout to which this filter is associated.
    const wchar_t* name;        ///< Display name of filter.
    const wchar_t* description; ///< Description of filter.
} net_ebpf_extension_wfp_filter_parameters_t;

typedef struct _net_ebpf_ext_sublayer_info
{
    const GUID* sublayer_guid;
    const wchar_t* name;
    const wchar_t* description;
    const uint32_t flags;
    const uint16_t weight;
} net_ebpf_ext_sublayer_info_t;

typedef struct _net_ebpf_extension_wfp_filter_parameters_array
{
    ebpf_attach_type_t* attach_type;
    uint32_t count;
    net_ebpf_extension_wfp_filter_parameters_t* filter_parameters;
} net_ebpf_extension_wfp_filter_parameters_array_t;

/**
 * "Base class" for all WFP filter contexts used by net ebpf extension hooks.
 */
typedef struct _net_ebpf_extension_wfp_filter_context
{
    volatile long reference_count;                                ///< Reference count.
    const struct _net_ebpf_extension_hook_client* client_context; ///< Pointer to hook NPI client.
    uint64_t* filter_ids;                                         ///< Array of WFP filter Ids.
    uint32_t filter_ids_count;                                    ///< Number of WFP filter Ids.
} net_ebpf_extension_wfp_filter_context_t;

#define REFERENCE_FILTER_CONTEXT(filter_context) \
    if ((filter_context) != NULL)                \
        InterlockedIncrement(&(filter_context)->reference_count);

#define DEREFERENCE_FILTER_CONTEXT(filter_context)                         \
    if ((filter_context) != NULL)                                          \
        if (InterlockedDecrement(&(filter_context)->reference_count) == 0) \
            ExFreePool((filter_context));

/**
 * @brief This function allocates and initializes a net ebpf extension WFP filter context. This should be invoked when
 * the hook client is being attached.
 *
 * @param[in] filter_context_size Size in bytes of the filter context.
 * @param[in] client_context Pointer to hook client being attached. This would be associated with the filter context.
 * @param[out] filter_context Pointer to created filter_context.
 *
 * @retval EBPF_SUCCESS The filter context was created successfully.
 * @retval EBPF_NO_MEMORY Out of memory.
 */
_Must_inspect_result_ ebpf_result_t
net_ebpf_extension_wfp_filter_context_create(
    size_t filter_context_size,
    _In_ const struct _net_ebpf_extension_hook_client* client_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context);

/**
 * @brief This function cleans up the input ebpf extension WFP filter context. This should be invoked when the hook
 * client is being detached.
 *
 * @param[out] filter_context Pointer to filter_context to clean up.
 *
 */
void
net_ebpf_extension_wfp_filter_context_cleanup(_Frees_ptr_ net_ebpf_extension_wfp_filter_context_t* filter_context);

/**
 * @brief Structure for WFP flow Id parameters.
 */
typedef struct _net_ebpf_extension_flow_context_parameters
{
    uint64_t flow_id;    ///< WFP flow Id.
    uint16_t layer_id;   ///< WFP layer Id that this flow is associated to.
    uint32_t callout_id; ///< WFP callout Id that this flow is associated to.
} net_ebpf_extension_flow_context_parameters_t;

typedef enum _net_ebpf_extension_hook_id
{
    EBPF_HOOK_OUTBOUND_L2 = 0,
    EBPF_HOOK_INBOUND_L2,
    EBPF_HOOK_ALE_RESOURCE_ALLOC_V4,
    EBPF_HOOK_ALE_RESOURCE_ALLOC_V6,
    EBPF_HOOK_ALE_RESOURCE_RELEASE_V4,
    EBPF_HOOK_ALE_RESOURCE_RELEASE_V6, // 5
    EBPF_HOOK_ALE_AUTH_CONNECT_V4,
    EBPF_HOOK_ALE_AUTH_CONNECT_V6,
    EBPF_HOOK_ALE_CONNECT_REDIRECT_V4,
    EBPF_HOOK_ALE_CONNECT_REDIRECT_V6,
    EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4, // 10
    EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6,
    EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4,
    EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6
} net_ebpf_extension_hook_id_t;

/**
 * @brief Helper function to return the eBPF network extension hook Id for the input WFP layer Id.
 *
 * @param[in] wfp_layer_id WFP layer Id.
 *
 * @returns eBPF network extension hook Id for the input WFP layer Id.
 */
net_ebpf_extension_hook_id_t
net_ebpf_extension_get_hook_id_from_wfp_layer_id(uint16_t wfp_layer_id);

/**
 * @brief Helper function to return the assigned Id for the WFP callout corresponding to the eBPF hook.
 *
 * @param[in] hook_id eBPF network extension hook id.
 *
 * @returns assigned Id for the WFP callout corresponding to the eBPF hook.
 */
uint32_t
net_ebpf_extension_get_callout_id_for_hook(net_ebpf_extension_hook_id_t hook_id);

/**
 * @brief Add WFP filters with specified conditions at specified layers.
 *
 * @param[in]  filter_count Count of filters to be added.
 * @param[in]  parameters Filter parameters.
 * @param[in]  condition_count Count of filter conditions.
 * @param[in]  conditions Common filter conditions to be applied to each filter.
 * @param[in, out]  filter_context Caller supplied context to be associated with the WFP filter.
 * @param[out] filter_ids Output buffer where the added filter IDs are stored.
 *
 * @retval EBPF_SUCCESS The operation completed successfully.
 * @retval EBPF_INVALID_ARGUMENT One or more arguments are invalid.
 */
_Must_inspect_result_ ebpf_result_t
net_ebpf_extension_add_wfp_filters(
    uint32_t filter_count,
    _In_count_(filter_count) const net_ebpf_extension_wfp_filter_parameters_t* parameters,
    uint32_t condition_count,
    _In_opt_count_(condition_count) const FWPM_FILTER_CONDITION* conditions,
    _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _Outptr_result_buffer_maybenull_(filter_count) uint64_t** filter_ids);

/**
 * @brief Deletes WFP filters with specified filter IDs.
 *
 * @param[in]  filter_count Count of filters to be added.
 * @param[in]  filter_ids ID of the filter being deleted.
 */
void
net_ebpf_extension_delete_wfp_filters(uint32_t filter_count, _Frees_ptr_ _In_count_(filter_count) uint64_t* filter_ids);

// eBPF WFP Provider GUID.
// ddb851f5-841a-4b77-8a46-bb7063e9f162
DEFINE_GUID(EBPF_WFP_PROVIDER, 0xddb851f5, 0x841a, 0x4b77, 0x8a, 0x46, 0xbb, 0x70, 0x63, 0xe9, 0xf1, 0x62);

// Default eBPF WFP Sublayer GUID.
// 7c7b3fb9-3331-436a-98e1-b901df457fff
DEFINE_GUID(EBPF_DEFAULT_SUBLAYER, 0x7c7b3fb9, 0x3331, 0x436a, 0x98, 0xe1, 0xb9, 0x01, 0xdf, 0x45, 0x7f, 0xff);

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

NTSTATUS
net_ebpf_ext_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ FWPS_FILTER* filter);
