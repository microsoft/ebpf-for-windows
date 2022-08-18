// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "fw_thunk.h"

NTSTATUS
FwpmFilterDeleteById0(_In_ HANDLE engineHandle, _In_ UINT64 id) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpmTransactionBegin0(_In_ _Acquires_lock_(_Curr_) HANDLE engineHandle, _In_ UINT32 flags) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpmFilterAdd0(
    _In_ HANDLE engineHandle, _In_ const FWPM_FILTER0* filter, _In_opt_ PSECURITY_DESCRIPTOR sd, _Out_opt_ UINT64* id)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpmTransactionCommit0(_In_ _Releases_lock_(_Curr_) HANDLE engineHandle) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpmTransactionAbort0(_In_ _Releases_lock_(_Curr_) HANDLE engineHandle) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpsCalloutRegister3(_Inout_ void* deviceObject, _In_ const FWPS_CALLOUT3* callout, _Out_opt_ UINT32* calloutId)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpmCalloutAdd0(
    _In_ HANDLE engineHandle, _In_ const FWPM_CALLOUT0* callout, _In_opt_ PSECURITY_DESCRIPTOR sd, _Out_opt_ UINT32* id)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpsCalloutUnregisterById0(_In_ const UINT32 calloutId) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpmEngineOpen0(
    _In_opt_ const wchar_t* serverName,
    _In_ UINT32 authnService,
    _In_opt_ SEC_WINNT_AUTH_IDENTITY_W* authIdentity,
    _In_opt_ const FWPM_SESSION0* session,
    _Out_ HANDLE* engineHandle)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpmSubLayerAdd0(_In_ HANDLE engineHandle, _In_ const FWPM_SUBLAYER0* subLayer, _In_opt_ PSECURITY_DESCRIPTOR sd)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpsInjectionHandleCreate0(_In_opt_ ADDRESS_FAMILY addressFamily, _In_ UINT32 flags, _Out_ HANDLE* injectionHandle)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpmEngineClose0(_Inout_ HANDLE engineHandle) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpsInjectionHandleDestroy0(_In_ HANDLE injectionHandle) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpsFlowRemoveContext0(_In_ UINT64 flowId, _In_ UINT16 layerId, _In_ UINT32 calloutId) { return STATUS_NO_MEMORY; }

NTSTATUS

FwpsFlowAssociateContext0(_In_ UINT64 flowId, _In_ UINT16 layerId, _In_ UINT32 calloutId, _In_ UINT64 flowContext)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpsAllocateNetBufferAndNetBufferList0(
    _In_ NDIS_HANDLE poolHandle,
    _In_ USHORT contextSize,
    _In_ USHORT contextBackFill,
    _In_opt_ MDL* mdlChain,
    _In_ ULONG dataOffset,
    _In_ SIZE_T dataLength,
    _Outptr_ NET_BUFFER_LIST** netBufferList)
{
    return STATUS_NO_MEMORY;
}

void
FwpsFreeNetBufferList0(_In_ NET_BUFFER_LIST* netBufferList)
{
    return;
}

NTSTATUS
FwpsInjectMacReceiveAsync0(
    _In_ HANDLE injectionHandle,
    _In_opt_ HANDLE injectionContext,
    _In_ UINT32 flags,
    _In_ UINT16 layerId,
    _In_ IF_INDEX interfaceIndex,
    _In_ NDIS_PORT_NUMBER NdisPortNumber,
    _Inout_ NET_BUFFER_LIST* netBufferLists,
    _In_ void* completionFn,
    _In_opt_ HANDLE completionContext)
{
    return STATUS_NO_MEMORY;
}

void
FwpsFreeCloneNetBufferList0(_In_ NET_BUFFER_LIST* netBufferList, _In_ ULONG freeCloneFlags)
{
    return;
}

NTSTATUS
FwpsAllocateCloneNetBufferList0(
    _Inout_ NET_BUFFER_LIST* originalNetBufferList,
    _In_opt_ NDIS_HANDLE netBufferListPoolHandle,
    _In_opt_ NDIS_HANDLE netBufferPoolHandle,
    _In_ ULONG allocateCloneFlags,
    _Outptr_ NET_BUFFER_LIST** netBufferList)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpsInjectMacSendAsync0(
    _In_ HANDLE injectionHandle,
    _In_opt_ HANDLE injectionContext,
    _In_ UINT32 flags,
    _In_ UINT16 layerId,
    _In_ IF_INDEX interfaceIndex,
    _In_ NDIS_PORT_NUMBER NdisPortNumber,
    _Inout_ NET_BUFFER_LIST* netBufferLists,
    _In_ void* completionFn,
    _In_opt_ HANDLE completionContext)
{
    return STATUS_NO_MEMORY;
}