// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"

typedef struct _NDIS_GENERIC_OBJECT
{
    DRIVER_OBJECT* driver_object;
    unsigned long tag;
} NDIS_GENERIC_OBJECT, *PNDIS_GENERIC_OBJECT;

typedef struct _NDIS_BUFFER_LIST_POOL
{
    NDIS_HANDLE ndis_handle;
    NET_BUFFER_LIST_POOL_PARAMETERS parameters;
} NDIS_BUFFER_LIST_POOL;

PNDIS_GENERIC_OBJECT
NdisAllocateGenericObject(_In_opt_ DRIVER_OBJECT* driver_object, _In_ unsigned long tag, _In_ uint16_t size)
{
    PNDIS_GENERIC_OBJECT object = reinterpret_cast<NDIS_GENERIC_OBJECT*>(malloc(sizeof(NDIS_GENERIC_OBJECT) + size));
    if (object) {
        object->driver_object = driver_object;
        object->tag = tag;
    }

    return object;
}

NDIS_HANDLE
NdisAllocateNetBufferListPool(_In_opt_ NDIS_HANDLE ndis_handle, _In_ NET_BUFFER_LIST_POOL_PARAMETERS const* parameters)
{
    NDIS_BUFFER_LIST_POOL* pool = reinterpret_cast<NDIS_BUFFER_LIST_POOL*>(malloc(sizeof(NDIS_BUFFER_LIST_POOL)));
    if (pool) {
        pool->ndis_handle = ndis_handle;
        pool->parameters = *parameters;
    }
    return pool;
}

void
NdisFreeNetBufferListPool(_In_ __drv_freesMem(mem) NDIS_HANDLE pool_handle)
{
    free(pool_handle);
}

PNET_BUFFER_LIST
NdisAllocateNetBufferList(_In_ NDIS_HANDLE nbl_pool_handle, _In_ USHORT context_size, _In_ USHORT context_backfill)
{
    UNREFERENCED_PARAMETER(nbl_pool_handle);
    UNREFERENCED_PARAMETER(context_size);
    UNREFERENCED_PARAMETER(context_backfill);
    return reinterpret_cast<NET_BUFFER_LIST*>(malloc(sizeof(NET_BUFFER_LIST)));
}

VOID
NdisFreeNetBufferList(_In_ __drv_freesMem(mem) NET_BUFFER_LIST* net_buffer_list)
{
    free(net_buffer_list);
}

NET_BUFFER_LIST*
NdisAllocateCloneNetBufferList(
    _In_ NET_BUFFER_LIST* original_net_buffer_list,
    _In_ NDIS_HANDLE net_buffer_list_pool_handle,
    _In_ NDIS_HANDLE net_buffer_pool_handle,
    ULONG allocate_clone_flags)
{
    UNREFERENCED_PARAMETER(allocate_clone_flags);
    NET_BUFFER_LIST* nbl = NdisAllocateNetBufferList(net_buffer_list_pool_handle, 0, 0);
    if (!nbl) {
        return nullptr;
    }
    NET_BUFFER* original_nb = original_net_buffer_list->FirstNetBuffer;
    NET_BUFFER* nb = NdisAllocateNetBuffer(net_buffer_pool_handle, original_nb->MdlChain, 0, original_nb->DataLength);
    if (!nb) {
        NdisFreeNetBufferList(nbl);
        return nullptr;
    }
    nbl->FirstNetBuffer = nb;
    return nbl;
}

void
NdisFreeCloneNetBufferList(_In_ NET_BUFFER_LIST* clone_net_buffer_list, ULONG free_clone_flags)
{
    UNREFERENCED_PARAMETER(free_clone_flags);
    return NdisFreeNetBufferList(clone_net_buffer_list);
}

void
NdisFreeGenericObject(_In_ PNDIS_GENERIC_OBJECT ndis_object)
{
    free(ndis_object);
}

_Must_inspect_result_ __drv_allocatesMem(mem) NET_BUFFER* NdisAllocateNetBuffer(
    _In_ NDIS_HANDLE pool_handle, _In_opt_ MDL* mdl_chain, _In_ unsigned long data_offset, _In_ SIZE_T data_length)
{
    UNREFERENCED_PARAMETER(pool_handle);
    UNREFERENCED_PARAMETER(data_offset);
    NET_BUFFER* nb = reinterpret_cast<NET_BUFFER*>(malloc(sizeof(*nb) + data_length));
    if (nb) {
        nb->DataLength = (unsigned long)data_length;
        nb->MdlChain = mdl_chain;
    }
    return nb;
}

VOID
NdisFreeNetBuffer(_In_ __drv_freesMem(mem) NET_BUFFER* net_buffer)
{
    free(net_buffer);
}

void*
NdisGetDataBuffer(
    _In_ NET_BUFFER* net_buffer,
    _In_ unsigned long bytes_needed,
    _Out_writes_bytes_all_opt_(bytes_needed) void* storage,
    _In_ unsigned long align_multiple,
    _In_ unsigned long align_offset)
{
    UNREFERENCED_PARAMETER(net_buffer);
    UNREFERENCED_PARAMETER(storage);
    UNREFERENCED_PARAMETER(align_multiple);
    UNREFERENCED_PARAMETER(align_offset);
    unsigned long size = MmGetMdlByteCount(net_buffer->MdlChain);
    if (size >= bytes_needed) {
        return MmGetSystemAddressForMdlSafe(net_buffer->MdlChain, NormalPagePriority);
    }
    return nullptr;
}

NDIS_STATUS
NdisRetreatNetBufferDataStart(
    _In_ NET_BUFFER* net_buffer,
    _In_ unsigned long data_offset_delta,
    _In_ unsigned long data_back_fill,
    _In_opt_ void* allocate_mdl_handler)
{
    UNREFERENCED_PARAMETER(net_buffer);
    UNREFERENCED_PARAMETER(data_offset_delta);
    UNREFERENCED_PARAMETER(data_back_fill);
    UNREFERENCED_PARAMETER(allocate_mdl_handler);
    return STATUS_NOT_IMPLEMENTED;
}

void
NdisAdvanceNetBufferDataStart(
    _In_ NET_BUFFER* net_buffer,
    _In_ unsigned long data_offset_delta,
    _In_ BOOLEAN free_mdl,
    _In_opt_ void* free_mdl_handler)
{
    UNREFERENCED_PARAMETER(free_mdl);
    UNREFERENCED_PARAMETER(free_mdl_handler);
    MDL* mdl_chain = net_buffer->MdlChain;
    mdl_chain->byte_offset += data_offset_delta;
}
