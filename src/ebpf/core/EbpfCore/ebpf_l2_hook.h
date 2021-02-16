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
#include "types.h"

//
// Shared function prototypes
//

NTSTATUS
ebpf_hook_register_callouts(
    _Inout_ void* device_object
);

void
ebpf_hook_unregister_callouts(void);

void
ebpf_hook_layer_2_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output);

void
ebpf_hook_layer_2_flow_delete(
    _In_ UINT16 layer_id,
    _In_ UINT32 fwpm_callout_id,
    _In_ UINT64 flow_context);

NTSTATUS
ebpf_hook_layer_2_notify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type,
    _In_ const GUID* filter_key,
    _Inout_ const FWPS_FILTER* filter);

