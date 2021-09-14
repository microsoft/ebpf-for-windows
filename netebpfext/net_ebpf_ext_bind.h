// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "net_ebpf_ext.h"

// Callout and sublayer GUIDs

// 732acf94-7319-4fed-97d0-41d3a18f3fa1
DEFINE_GUID(
    EBPF_HOOK_ALE_RESOURCE_ALLOC_CALLOUT, 0x732acf94, 0x7319, 0x4fed, 0x97, 0xd0, 0x41, 0xd3, 0xa1, 0x8f, 0x3f, 0xa1);

// d5792949-2d91-4023-9993-3f3dd9d54b2b
DEFINE_GUID(
    EBPF_HOOK_ALE_RESOURCE_RELEASE_CALLOUT, 0xd5792949, 0x2d91, 0x4023, 0x99, 0x93, 0x3f, 0x3d, 0xd9, 0xd5, 0x4b, 0x2b);

/**
 * @brief WFP classifyFn callback for EBPF_HOOK_ALE_RESOURCE_ALLOC_CALLOUT.
 *
 */
void
net_ebpf_ext_resource_allocation_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output);

/**
 * @brief WFP classifyFn callback for EBPF_HOOK_ALE_RESOURCE_RELEASE_CALLOUT.
 *
 */
void
net_ebpf_ext_resource_release_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output);

/**
 * @brief Unregister BIND NPI providers.
 *
 */
void
net_ebpf_ext_bind_unregister_providers();

/**
 * @brief Register BIND NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
net_ebpf_ext_bind_register_providers();
