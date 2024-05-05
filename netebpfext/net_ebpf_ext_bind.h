// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "net_ebpf_ext.h"

// Callout and sublayer GUIDs

// 732acf94-7319-4fed-97d0-41d3a18f3fa1
DEFINE_GUID(
    EBPF_HOOK_ALE_RESOURCE_ALLOC_V4_CALLOUT,
    0x732acf94,
    0x7319,
    0x4fed,
    0x97,
    0xd0,
    0x41,
    0xd3,
    0xa1,
    0x8f,
    0x3f,
    0xa1);

// d5792949-2d91-4023-9993-3f3dd9d54b2b
DEFINE_GUID(
    EBPF_HOOK_ALE_RESOURCE_RELEASE_V4_CALLOUT,
    0xd5792949,
    0x2d91,
    0x4023,
    0x99,
    0x93,
    0x3f,
    0x3d,
    0xd9,
    0xd5,
    0x4b,
    0x2b);

// 01b9f024-8f42-49f7-b7c0-888266e5402a
DEFINE_GUID(
    EBPF_HOOK_ALE_RESOURCE_ALLOC_V6_CALLOUT,
    0x01b9f024,
    0x8f42,
    0x49f7,
    0xb7,
    0xc0,
    0x88,
    0x82,
    0x66,
    0xe5,
    0x40,
    0x2a);

// b70a421a-9fe3-11ec-9a30-18602489beee
DEFINE_GUID(
    EBPF_HOOK_ALE_RESOURCE_RELEASE_V6_CALLOUT,
    0xb70a421a,
    0x9fe3,
    0x11ec,
    0x9a,
    0x30,
    0x18,
    0x60,
    0x24,
    0x89,
    0xbe,
    0xee);

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
