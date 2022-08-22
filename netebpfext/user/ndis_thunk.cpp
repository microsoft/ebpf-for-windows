// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "ndis_thunk.h"

PNDIS_GENERIC_OBJECT
NdisAllocateGenericObject(_In_opt_ DRIVER_OBJECT* DriverObject, _In_ unsigned long tag, _In_ uint16_t Size)
{
    return NULL;
}

NDIS_HANDLE
NdisAllocateNetBufferListPool(_In_opt_ NDIS_HANDLE NdisHandle, _In_ NET_BUFFER_LIST_POOL_PARAMETERS const* Parameters)
{
    return NULL;
}

void
NdisFreeNetBufferListPool(_In_ __drv_freesMem(mem) NDIS_HANDLE PoolHandle)
{
    return;
}

void
NdisFreeGenericObject(_In_ PNDIS_GENERIC_OBJECT NdisObject)
{
    return;
}

void*
NdisGetDataBuffer(
    _In_ NET_BUFFER* NetBuffer,
    _In_ unsigned long BytesNeeded,
    _Out_writes_bytes_all_opt_(BytesNeeded) void* Storage,
    _In_ unsigned long AlignMultiple,
    _In_ unsigned long AlignOffset)
{
    return NULL;
}

NDIS_STATUS
NdisRetreatNetBufferDataStart(
    _In_ NET_BUFFER* NetBuffer,
    _In_ unsigned long DataOffsetDelta,
    _In_ unsigned long DataBackFill,
    _In_opt_ void* AllocateMdlHandler)
{
    return STATUS_NO_MEMORY;
}

void
NdisAdvanceNetBufferDataStart(
    _In_ NET_BUFFER* NetBuffer, _In_ unsigned long DataOffsetDelta, _In_ BOOLEAN FreeMdl, _In_opt_ void* FreeMdlHandler)
{
    return;
}
