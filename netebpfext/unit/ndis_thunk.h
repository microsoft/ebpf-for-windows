// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "kernel_thunk.h"

#define NET_BUFFER_FIRST_MDL(_NB) ((_NB)->MdlChain)
#define NDIS_STATUS_SUCCESS ((NDIS_STATUS)STATUS_SUCCESS)
#define NET_BUFFER_LIST_FIRST_NB(_NBL) ((_NBL)->FirstNetBuffer)
#define NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 1
#define NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 \
    RTL_SIZEOF_THROUGH_FIELD(NET_BUFFER_LIST_POOL_PARAMETERS, DataSize)

typedef struct _NET_BUFFER_LIST_POOL_PARAMETERS
{
    /*
        Parameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        Parameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        Parameters.Header.Size = sizeof(Parameters);
    */
    NDIS_OBJECT_HEADER Header;
    UCHAR ProtocolId;
    BOOLEAN fAllocateNetBuffer;
    USHORT ContextSize;
    ULONG PoolTag;
    ULONG DataSize;
} NET_BUFFER_LIST_POOL_PARAMETERS, *PNET_BUFFER_LIST_POOL_PARAMETERS;

typedef struct _NET_BUFFER
{
    MDL* MdlChain;
    ULONG DataLength;
} NET_BUFFER, *PNET_BUFFER;

typedef struct _NET_BUFFER_LIST_CONTEXT NET_BUFFER_LIST_CONTEXT, *PNET_BUFFER_LIST_CONTEXT;

typedef struct _NET_BUFFER_LIST
{
    NET_BUFFER* FirstNetBuffer;
} NET_BUFFER_LIST, *PNET_BUFFER_LIST;

typedef void* PNDIS_GENERIC_OBJECT;

PNDIS_GENERIC_OBJECT
NdisAllocateGenericObject(_In_opt_ DRIVER_OBJECT* DriverObject, _In_ ULONG tag, _In_ USHORT Size);

NDIS_HANDLE
NdisAllocateNetBufferListPool(_In_opt_ NDIS_HANDLE NdisHandle, _In_ NET_BUFFER_LIST_POOL_PARAMETERS const* Parameters);

VOID
NdisFreeNetBufferListPool(_In_ __drv_freesMem(mem) NDIS_HANDLE PoolHandle);

VOID
NdisFreeGenericObject(_In_ PNDIS_GENERIC_OBJECT NdisObject);

void*
NdisGetDataBuffer(
    _In_ NET_BUFFER* NetBuffer,
    _In_ ULONG BytesNeeded,
    _Out_writes_bytes_all_opt_(BytesNeeded) void* Storage,
    _In_ ULONG AlignMultiple,
    _In_ ULONG AlignOffset);

NDIS_STATUS
NdisRetreatNetBufferDataStart(
    _In_ NET_BUFFER* NetBuffer, _In_ ULONG DataOffsetDelta, _In_ ULONG DataBackFill, _In_opt_ void* AllocateMdlHandler);

VOID
NdisAdvanceNetBufferDataStart(
    _In_ NET_BUFFER* NetBuffer, _In_ ULONG DataOffsetDelta, _In_ BOOLEAN FreeMdl, _In_opt_ void* FreeMdlHandler);
