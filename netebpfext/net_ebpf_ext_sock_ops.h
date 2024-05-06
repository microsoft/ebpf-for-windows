// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "net_ebpf_ext.h"

// Callout GUIDs

// f53b4577-bc47-11ec-9a30-18602489beee
DEFINE_GUID(
    EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4_CALLOUT,
    0xf53b4577,
    0xbc47,
    0x11ec,
    0x9a,
    0x30,
    0x18,
    0x60,
    0x24,
    0x89,
    0xbe,
    0xee);

// f53b4578-bc47-11ec-9a30-18602489beee
DEFINE_GUID(
    EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6_CALLOUT,
    0xf53b4578,
    0xbc47,
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
 * @brief WFP classifyFn callback for EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4/6_CALLOUT.
 */
void
net_ebpf_extension_sock_ops_flow_established_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output);

/**
 * @brief WFP flowDeleteFn callback for EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4/6_CALLOUT.
 */
void
net_ebpf_extension_sock_ops_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context);

/**
 * @brief Unregister SOCK_OPS NPI providers.
 *
 */
void
net_ebpf_ext_sock_ops_unregister_providers();

/**
 * @brief Register SOCK_OPS NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
net_ebpf_ext_sock_ops_register_providers();
