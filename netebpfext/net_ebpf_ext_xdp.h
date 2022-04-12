// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include "net_ebpf_ext.h"

// Callout GUIDs

// 5a5614e4-6b64-4738-8367-33c6ca07bf8f
DEFINE_GUID(EBPF_HOOK_OUTBOUND_L2_CALLOUT, 0x5a5614e4, 0x6b64, 0x4738, 0x83, 0x67, 0x33, 0xc6, 0xca, 0x07, 0xbf, 0x8f);

// 5a5614e5-6b64-4738-8367-33c6ca07bf8f
DEFINE_GUID(EBPF_HOOK_INBOUND_L2_CALLOUT, 0x5a5614e5, 0x6b64, 0x4738, 0x83, 0x67, 0x33, 0xc6, 0xca, 0x07, 0xbf, 0x8f);

/**
 * @brief Common WFP classifyFn callback for EBPF_HOOK_OUTBOUND_L2_CALLOUT and EBPF_HOOK_INBOUND_L2_CALLOUT.
 *
 */
void
net_ebpf_ext_layer_2_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output);

/**
 * @brief Unregister XDP NPI providers.
 *
 */
void
net_ebpf_ext_xdp_unregister_providers();

/**
 * @brief Register XDP NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
net_ebpf_ext_xdp_register_providers();
