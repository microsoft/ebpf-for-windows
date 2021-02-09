/*++

Copyright (c) Microsoft Corporation. All rights reserved

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
HANDLE gEngineHandle;
UINT32 gL2CalloutId;

extern INT32 ExecuteCodeAtHook(_In_ void* ctx);

NTSTATUS
EbpfHookAddFilter(
    _In_ const PWSTR filterName,
    _In_ const PWSTR filterDesc,
    _In_ FWP_DIRECTION direction,
    _In_ const GUID* layerKey,
    _In_ const GUID* calloutKey
)
{
    UNREFERENCED_PARAMETER(direction);
    NTSTATUS status = STATUS_SUCCESS;

    FWPM_FILTER filter = { 0 };
    FWPM_FILTER_CONDITION filterConditions[3] = { 0 };
    UINT conditionIndex;

    filter.layerKey = *layerKey;
    filter.displayData.name = (wchar_t*)filterName;
    filter.displayData.description = (wchar_t*)filterDesc;

    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *calloutKey;
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
        gEngineHandle,
        &filter,
        NULL,
        NULL);

    return status;
}


NTSTATUS
EbpfHookRegisterL2Callout(
    _In_ const GUID* layerKey,
    _In_ const GUID* calloutKey,
    _Inout_ void* deviceObject,
    _Out_ UINT32* calloutId
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

    sCallout.calloutKey = *calloutKey;
    sCallout.classifyFn = EbpfHookL2Classify;
    sCallout.notifyFn = EbpfHookL2Notify;
    sCallout.flowDeleteFn = EbpfHookL2FlowDelete;
    sCallout.flags = 0;

    status = FwpsCalloutRegister(
        deviceObject,
        &sCallout,
        calloutId
    );
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    calloutRegistered = TRUE;

    displayData.name = L"L2 XDP Callout";
    displayData.description = L"L2 callout driver for eBPF at XDP-like layer";

    mCallout.calloutKey = *calloutKey;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = *layerKey;

    status = FwpmCalloutAdd(
        gEngineHandle,
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
        layerKey,
        calloutKey
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
            FwpsCalloutUnregisterById(*calloutId);
            *calloutId = 0;
        }
    }

    return status;
}

NTSTATUS
EbpfHookRegisterCallouts(
    _Inout_ void* deviceObject
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

    if (gEngineHandle != NULL)
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
        &gEngineHandle
    );
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    engineOpened = TRUE;

    status = FwpmTransactionBegin(gEngineHandle, 0);
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

    status = FwpmSubLayerAdd(gEngineHandle, &ebpfHookL2SubLayer, NULL);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = EbpfHookRegisterL2Callout(
        &FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET,
        &EBPF_HOOK_L2_CALLOUT,
        deviceObject,
        &gL2CalloutId
    );
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = FwpmTransactionCommit(gEngineHandle);
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
            FwpmTransactionAbort(gEngineHandle);
            _Analysis_assume_lock_not_held_(gEngineHandle); // Potential leak if "FwpmTransactionAbort" fails
        }
        if (engineOpened)
        {
            FwpmEngineClose(gEngineHandle);
            gEngineHandle = NULL;
        }
    }

    return status;
}

void
EbpfHookUnregisterCallouts(void)
{
    if (gEngineHandle != NULL)
    {
        FwpmEngineClose(gEngineHandle);
        gEngineHandle = NULL;

        FwpsCalloutUnregisterById(gL2CalloutId);
    }
}

void
EbpfHookL2Classify(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues,
   _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   _Inout_opt_ void* layerData,
   _In_opt_ const void* classifyContext,
   _In_ const FWPS_FILTER* filter,
   _In_ UINT64 flowContext,
   _Inout_ FWPS_CLASSIFY_OUT* classifyOut
   )
/* ++

   A simple classify function at the WFP L2 MAC layer.

-- */
{
   FWP_ACTION_TYPE action = FWP_ACTION_PERMIT;
   UNREFERENCED_PARAMETER(inFixedValues);
   UNREFERENCED_PARAMETER(inMetaValues);
   UNREFERENCED_PARAMETER(classifyContext);
   UNREFERENCED_PARAMETER(filter);
   UNREFERENCED_PARAMETER(flowContext);
   NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
   NET_BUFFER* netBuffer = NULL;
   BYTE* mdlAddr;
   UINT32 result = 0;

   if (nbl == NULL)
   {
       KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Null nbl \n"));
       goto done;
   }

   netBuffer = NET_BUFFER_LIST_FIRST_NB(nbl);
   if (netBuffer == NULL)
   {
       KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "netbuffer not present\n"));
       // nothing to do
       goto done;
   }

   mdlAddr =
       NdisGetDataBuffer(
           netBuffer,
           sizeof(IPV4_HEADER) + max(sizeof(TCP_HEADER), sizeof(UDP_HEADER)),
           NULL,
           sizeof(UINT16),
           0);

   // execute code at hook.
   result = ExecuteCodeAtHook(mdlAddr);
   if (result == 1)
   {
       action = FWP_ACTION_PERMIT;
   }
   else if (result == 2)
   {
       action = FWP_ACTION_BLOCK;
   }

done:   
   classifyOut->actionType = action;
   return;
}

NTSTATUS
EbpfHookL2Notify(
   _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
   _In_ const GUID* filterKey,
   _Inout_ const FWPS_FILTER* filter
   )
{
   UNREFERENCED_PARAMETER(notifyType);
   UNREFERENCED_PARAMETER(filterKey);
   UNREFERENCED_PARAMETER(filter);

   return STATUS_SUCCESS;
}

void
EbpfHookL2FlowDelete(
   _In_ UINT16 layerId,
   _In_ UINT32 calloutId,
   _In_ UINT64 flowContext
   )
/* ++

   This is the flowDeleteFn function of the L2 callout. 

-- */
{
   UNREFERENCED_PARAMETER(layerId);
   UNREFERENCED_PARAMETER(calloutId);
   UNREFERENCED_PARAMETER(flowContext);
   return;
}
