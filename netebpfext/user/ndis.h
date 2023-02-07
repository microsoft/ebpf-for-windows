// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#define _NDIS_
#include "kernel_um.h"

#include <ndis/objectheader.h>
#include <ndis/types.h>

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
        Parameters.Header.size = sizeof(Parameters);
    */
    NDIS_OBJECT_HEADER Header;
    uint8_t ProtocolId;
    BOOLEAN fAllocateNetBuffer;
    uint16_t ContextSize;
    unsigned long PoolTag;
    unsigned long DataSize;
} NET_BUFFER_LIST_POOL_PARAMETERS, *PNET_BUFFER_LIST_POOL_PARAMETERS;

// We need the NET_BUFFER typedefs without the other NT kernel defines that
// ndis.h might pull in and conflict with user-mode headers.
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
#pragma warning(push)
#pragma warning(disable : 4324) // structure was padded due to alignment specifier
#include <ndis/nbl.h>
#pragma warning(pop)

typedef struct _NET_BUFFER_LIST_CONTEXT NET_BUFFER_LIST_CONTEXT, *PNET_BUFFER_LIST_CONTEXT;

typedef struct _NDIS_GENERIC_OBJECT NDIS_GENERIC_OBJECT, *PNDIS_GENERIC_OBJECT;

PNDIS_GENERIC_OBJECT
NdisAllocateGenericObject(_In_opt_ DRIVER_OBJECT* driver_object, _In_ unsigned long tag, _In_ uint16_t size);

NDIS_HANDLE
NdisAllocateNetBufferListPool(_In_opt_ NDIS_HANDLE ndis_handle, _In_ NET_BUFFER_LIST_POOL_PARAMETERS const* parameters);

NET_BUFFER_LIST*
NdisAllocateCloneNetBufferList(
    _In_ NET_BUFFER_LIST* original_net_buffer_list,
    _In_ NDIS_HANDLE net_buffer_list_pool_handle,
    _In_ NDIS_HANDLE net_buffer_pool_handle,
    ULONG allocate_clone_flags);

void
NdisFreeCloneNetBufferList(_In_ NET_BUFFER_LIST* clone_net_buffer_list, ULONG free_clone_flags);

PNET_BUFFER_LIST
NdisAllocateNetBufferList(_In_ NDIS_HANDLE nbl_pool_handle, _In_ USHORT context_size, _In_ USHORT context_backfill);

_Must_inspect_result_ __drv_allocatesMem(mem) NET_BUFFER* NdisAllocateNetBuffer(
    _In_ NDIS_HANDLE pool_handle, _In_opt_ MDL* mdl_chain, _In_ ULONG data_offset, _In_ SIZE_T data_length);

VOID
NdisFreeNetBuffer(_In_ __drv_freesMem(mem) NET_BUFFER* net_buffer);

VOID
NdisFreeNetBufferList(_In_ __drv_freesMem(mem) NET_BUFFER_LIST* net_buffer_list);

void
NdisFreeNetBufferListPool(_In_ __drv_freesMem(mem) NDIS_HANDLE pool_handle);

void
NdisFreeGenericObject(_In_ PNDIS_GENERIC_OBJECT ndis_object);

void*
NdisGetDataBuffer(
    _In_ NET_BUFFER* net_buffer,
    _In_ unsigned long bytes_needed,
    _Out_writes_bytes_all_opt_(bytes_needed) void* storage,
    _In_ unsigned long align_multiple,
    _In_ unsigned long align_offset);

NDIS_STATUS
NdisRetreatNetBufferDataStart(
    _In_ NET_BUFFER* net_buffer,
    _In_ unsigned long data_offset_delta,
    _In_ unsigned long data_back_fill,
    _In_opt_ void* allocate_mdl_handler);

void
NdisAdvanceNetBufferDataStart(
    _In_ NET_BUFFER* net_buffer,
    _In_ unsigned long data_offset_delta,
    _In_ BOOLEAN free_mdl,
    _In_opt_ void* free_mdl_handler);
