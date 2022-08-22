// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "ndis_thunk.h"

PNDIS_GENERIC_OBJECT
NdisAllocateGenericObject(_In_opt_ DRIVER_OBJECT* driver_object, _In_ unsigned long tag, _In_ uint16_t size)
{
    UNREFERENCED_PARAMETER(driver_object);
    UNREFERENCED_PARAMETER(tag);
    UNREFERENCED_PARAMETER(size);
    return NULL;
}

NDIS_HANDLE
NdisAllocateNetBufferListPool(_In_opt_ NDIS_HANDLE ndis_handle, _In_ NET_BUFFER_LIST_POOL_PARAMETERS const* parameters)
{
    UNREFERENCED_PARAMETER(ndis_handle);
    UNREFERENCED_PARAMETER(parameters);
    return NULL;
}

void
NdisFreeNetBufferListPool(_In_ __drv_freesMem(mem) NDIS_HANDLE pool_handle)
{
    UNREFERENCED_PARAMETER(pool_handle);
    return;
}

void
NdisFreeGenericObject(_In_ PNDIS_GENERIC_OBJECT ndis_object)
{
    UNREFERENCED_PARAMETER(ndis_object);
    return;
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
    UNREFERENCED_PARAMETER(bytes_needed);
    UNREFERENCED_PARAMETER(storage);
    UNREFERENCED_PARAMETER(align_multiple);
    UNREFERENCED_PARAMETER(align_offset);
    return NULL;
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
    return STATUS_NO_MEMORY;
}

void
NdisAdvanceNetBufferDataStart(
    _In_ NET_BUFFER* net_buffer,
    _In_ unsigned long data_offset_delta,
    _In_ BOOLEAN free_mdl,
    _In_opt_ void* free_mdl_handler)
{
    UNREFERENCED_PARAMETER(net_buffer);
    UNREFERENCED_PARAMETER(data_offset_delta);
    UNREFERENCED_PARAMETER(free_mdl);
    UNREFERENCED_PARAMETER(free_mdl_handler);
    return;
}
