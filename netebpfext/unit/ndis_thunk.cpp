// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "ndis_thunk.h"

PNDIS_GENERIC_OBJECT
NdisAllocateGenericObject(_In_opt_ DRIVER_OBJECT* DriverObject, _In_ ULONG tag, _In_ USHORT Size) { return NULL; }

NDIS_HANDLE
NdisAllocateNetBufferListPool(_In_opt_ NDIS_HANDLE NdisHandle, _In_ NET_BUFFER_LIST_POOL_PARAMETERS const* Parameters)
{
    return NULL;
}

VOID
NdisFreeNetBufferListPool(_In_ __drv_freesMem(mem) NDIS_HANDLE PoolHandle)
{
    return;
}

VOID
NdisFreeGenericObject(_In_ PNDIS_GENERIC_OBJECT NdisObject)
{
    return;
}

void*
NdisGetDataBuffer(
    _In_ NET_BUFFER* NetBuffer,
    _In_ ULONG BytesNeeded,
    _Out_writes_bytes_all_opt_(BytesNeeded) void* Storage,
    _In_ ULONG AlignMultiple,
    _In_ ULONG AlignOffset)
{
    return NULL;
}

NDIS_STATUS
NdisRetreatNetBufferDataStart(
    _In_ NET_BUFFER* NetBuffer, _In_ ULONG DataOffsetDelta, _In_ ULONG DataBackFill, _In_opt_ void* AllocateMdlHandler)
{
    return STATUS_NO_MEMORY;
}

VOID
NdisAdvanceNetBufferDataStart(
    _In_ NET_BUFFER* NetBuffer, _In_ ULONG DataOffsetDelta, _In_ BOOLEAN FreeMdl, _In_opt_ void* FreeMdlHandler)
{
    return;
}
