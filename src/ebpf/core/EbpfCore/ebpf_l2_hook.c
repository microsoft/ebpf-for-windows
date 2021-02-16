/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

/*++

Abstract:

   This file implements the classifyFn, notifiFn, and flowDeleteFn callout
   functions for the l2 callout.

Environment:

    Kernel mode

--*/

#include <ntddk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>
#include <netiodef.h>

#include "ebpf_l2_hook.h"

#define INITGUID
#include <guiddef.h>
#include "protocol.h"
#include "ebpf_core.h"

// Callout and sublayer GUIDs

// 5a5614e5-6b64-4738-8367-33c6ca07bf8f
DEFINE_GUID(
    EBPF_HOOK_L2_CALLOUT,
    0x5a5614e5,
    0x6b64,
    0x4738,
    0x83, 0x67, 0x33, 0xc6, 0xca, 0x07, 0xbf, 0x8f
);

// 7c7b3fb9-3331-436a-98e1-b901df457fff
DEFINE_GUID(
    EBPF_HOOK_SUBLAYER,
    0x7c7b3fb9,
    0x3331,
    0x436a,
    0x98, 0xe1, 0xb9, 0x01, 0xdf, 0x45, 0x7f, 0xff
);

// Callout globals
static HANDLE _fwp_engine_handle;
static UINT32 _fwp_layer_2_callout_id;

NTSTATUS
EbpfHookAddFilter(
    _In_ const PWSTR filter_name,
    _In_ const PWSTR filter_description,
    _In_ FWP_DIRECTION filter_direction,
    _In_ const GUID* fwpm_layer_key,
    _In_ const GUID* fwpm_callout_key
)
{
    UNREFERENCED_PARAMETER(filter_direction);
    NTSTATUS status = STATUS_SUCCESS;

    FWPM_FILTER filter = { 0 };
    FWPM_FILTER_CONDITION filterConditions[3] = { 0 };
    UINT conditionIndex;

    filter.layerKey = *fwpm_layer_key;
    filter.displayData.name = (wchar_t*)filter_name;
    filter.displayData.description = (wchar_t*)filter_description;

    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *fwpm_callout_key;
    filter.filterCondition = filterConditions;
    filter.subLayerKey = EBPF_HOOK_SUBLAYER;
    filter.weight.type = FWP_EMPTY; // auto-weight.
    //filter.rawContext = context;

    conditionIndex = 0;

    filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_ETHER_TYPE;
    filterConditions[conditionIndex].matchType = FWP_MATCH_EQUAL;
    filterConditions[conditionIndex].conditionValue.type = FWP_UINT16;
    filterConditions[conditionIndex].conditionValue.uint16 = NDIS_ETH_TYPE_IPV4;

    conditionIndex++;

    filter.numFilterConditions = conditionIndex;

    status = FwpmFilterAdd(
        _fwp_engine_handle,
        &filter,
        NULL,
        NULL);

    return status;
}


NTSTATUS
EbpfHookRegisterL2Callout(
    _In_ const GUID* fwpm_layer_key,
    _In_ const GUID* fwpm_callout_key,
    _Inout_ void* device_object,
    _Out_ UINT32* fwpm_callout_id
)
/* ++

   This function registers callouts and filters that intercept L2 traffic at
   WFP FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET.

-- */
{
    NTSTATUS status = STATUS_SUCCESS;

    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };

    FWPM_DISPLAY_DATA displayData = { 0 };

    BOOLEAN calloutRegistered = FALSE;

    sCallout.calloutKey = *fwpm_callout_key;
    sCallout.classifyFn = ebpf_hook_layer_2_classify;
    sCallout.notifyFn = ebpf_hook_layer_2_notify;
    sCallout.flowDeleteFn = ebpf_hook_layer_2_flow_delete;
    sCallout.flags = 0;

    status = FwpsCalloutRegister(
        device_object,
        &sCallout,
        fwpm_callout_id
    );
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    calloutRegistered = TRUE;

    displayData.name = L"L2 XDP Callout";
    displayData.description = L"L2 callout driver for eBPF at XDP-like layer";

    mCallout.calloutKey = *fwpm_callout_key;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = *fwpm_layer_key;

    status = FwpmCalloutAdd(
        _fwp_engine_handle,
        &mCallout,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = EbpfHookAddFilter(
        L"L2 filter (Inbound)",
        L"L2 filter inbound",
        FWP_DIRECTION_INBOUND,
        fwpm_layer_key,
        fwpm_callout_key
    );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

Exit:

    if (!NT_SUCCESS(status))
    {
        if (calloutRegistered)
        {
            FwpsCalloutUnregisterById(*fwpm_callout_id);
            *fwpm_callout_id = 0;
        }
    }

    return status;
}

NTSTATUS
ebpf_hook_register_callouts(
    _Inout_ void* device_object
)
/* ++

   This function registers dynamic callouts and filters that
   FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET layer.

   Callouts and filters will be removed during DriverUnload.

-- */
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SUBLAYER ebpfHookL2SubLayer;

    BOOLEAN engineOpened = FALSE;
    BOOLEAN inTransaction = FALSE;

    FWPM_SESSION session = { 0 };

    if (_fwp_engine_handle != NULL)
    {
        // already registered
        goto Exit;
    }

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &_fwp_engine_handle
    );
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    engineOpened = TRUE;

    status = FwpmTransactionBegin(_fwp_engine_handle, 0);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    inTransaction = TRUE;

    RtlZeroMemory(&ebpfHookL2SubLayer, sizeof(FWPM_SUBLAYER));

    ebpfHookL2SubLayer.subLayerKey = EBPF_HOOK_SUBLAYER;
    ebpfHookL2SubLayer.displayData.name = L"L2 hook Sub-Layer";
    ebpfHookL2SubLayer.displayData.description =
        L"Sub-Layer for use by L2 callouts";
    ebpfHookL2SubLayer.flags = 0;
    ebpfHookL2SubLayer.weight = FWP_EMPTY; // auto-weight.;

    status = FwpmSubLayerAdd(_fwp_engine_handle, &ebpfHookL2SubLayer, NULL);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = EbpfHookRegisterL2Callout(
        &FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET,
        &EBPF_HOOK_L2_CALLOUT,
        device_object,
        &_fwp_layer_2_callout_id
    );
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = FwpmTransactionCommit(_fwp_engine_handle);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    inTransaction = FALSE;

Exit:

    if (!NT_SUCCESS(status))
    {
        if (inTransaction)
        {
            FwpmTransactionAbort(_fwp_engine_handle);
            _Analysis_assume_lock_not_held_(_fwp_engine_handle); // Potential leak if "FwpmTransactionAbort" fails
        }
        if (engineOpened)
        {
            FwpmEngineClose(_fwp_engine_handle);
            _fwp_engine_handle = NULL;
        }
    }

    return status;
}

void
ebpf_hook_unregister_callouts(void)
{
    if (_fwp_engine_handle != NULL)
    {
        FwpmEngineClose(_fwp_engine_handle);
        _fwp_engine_handle = NULL;

        FwpsCalloutUnregisterById(_fwp_layer_2_callout_id);
    }
}

void
ebpf_hook_layer_2_classify(
   _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
   _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
   _Inout_opt_ void* layer_data,
   _In_opt_ const void* classify_context,
   _In_ const FWPS_FILTER* filter,
   _In_ UINT64 flow_context,
   _Inout_ FWPS_CLASSIFY_OUT* classify_output
   )
/* ++

   A simple classify function at the WFP L2 MAC layer.

-- */
{
   FWP_ACTION_TYPE action = FWP_ACTION_PERMIT;
   UNREFERENCED_PARAMETER(incoming_fixed_values);
   UNREFERENCED_PARAMETER(incoming_metadata_values);
   UNREFERENCED_PARAMETER(classify_context);
   UNREFERENCED_PARAMETER(filter);
   UNREFERENCED_PARAMETER(flow_context);
   NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layer_data;
   NET_BUFFER* net_buffer = NULL;
   BYTE* packet_buffer;
   UINT32 result = 0;

   if (nbl == NULL)
   {
       KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Null nbl \n"));
       goto done;
   }

   net_buffer = NET_BUFFER_LIST_FIRST_NB(nbl);
   if (net_buffer == NULL)
   {
       KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "net_buffer not present\n"));
       // nothing to do
       goto done;
   }


   packet_buffer =
       NdisGetDataBuffer(
           net_buffer,
           net_buffer->DataLength,
           NULL,
           sizeof(UINT16),
           0);
   
   // execute code at hook.
   result = ebpf_core_invoke_xdp_hook(packet_buffer, net_buffer->DataLength);
   switch (result)
   {
   case XDP_PASS:
       action = FWP_ACTION_PERMIT;
       break;
   case XDP_DROP:
       action = FWP_ACTION_BLOCK;
       break;
   }

done:   
   classify_output->actionType = action;
   return;
}

NTSTATUS
ebpf_hook_layer_2_notify(
   _In_ FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type,
   _In_ const GUID* filter_key,
   _Inout_ const FWPS_FILTER* filter
   )
{
   UNREFERENCED_PARAMETER(callout_notification_type);
   UNREFERENCED_PARAMETER(filter_key);
   UNREFERENCED_PARAMETER(filter);

   return STATUS_SUCCESS;
}

void
ebpf_hook_layer_2_flow_delete(
   _In_ UINT16 layer_id,
   _In_ UINT32 fwpm_callout_id,
   _In_ UINT64 flow_context
   )
/* ++

   This is the flowDeleteFn function of the L2 callout. 

-- */
{
   UNREFERENCED_PARAMETER(layer_id);
   UNREFERENCED_PARAMETER(fwpm_callout_id);
   UNREFERENCED_PARAMETER(flow_context);
   return;
}
