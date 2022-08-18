// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "fw_thunk.h"

NTSTATUS
FwpmFilterDeleteById0(_In_ HANDLE engine_handle, _In_ uint64_t id) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpmTransactionBegin0(_In_ _Acquires_lock_(_Curr_) HANDLE engine_handle, _In_ uint32_t flags)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpmFilterAdd0(
    _In_ HANDLE engine_handle,
    _In_ const FWPM_FILTER0* filter,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ uint64_t* id)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpmTransactionCommit0(_In_ _Releases_lock_(_Curr_) HANDLE engine_handle) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpmTransactionAbort0(_In_ _Releases_lock_(_Curr_) HANDLE engine_handle) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpsCalloutRegister3(_Inout_ void* device_object, _In_ const FWPS_CALLOUT3* callout, _Out_opt_ uint32_t* callout_id)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpmCalloutAdd0(
    _In_ HANDLE engine_handle,
    _In_ const FWPM_CALLOUT0* callout,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ uint32_t* id)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpsCalloutUnregisterById0(_In_ const uint32_t callout_id) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpmEngineOpen0(
    _In_opt_ const wchar_t* server_name,
    _In_ uint32_t authn_service,
    _In_opt_ SEC_WINNT_AUTH_IDENTITY_W* auth_identity,
    _In_opt_ const FWPM_SESSION0* session,
    _Out_ HANDLE* engine_handle)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpmSubLayerAdd0(_In_ HANDLE engine_handle, _In_ const FWPM_SUBLAYER0* sub_layer, _In_opt_ PSECURITY_DESCRIPTOR sd)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpsInjectionHandleCreate0(_In_opt_ ADDRESS_FAMILY address_family, _In_ uint32_t flags, _Out_ HANDLE* injection_handle)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpmEngineClose0(_Inout_ HANDLE engine_handle) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpsInjectionHandleDestroy0(_In_ HANDLE injection_handle) { return STATUS_NO_MEMORY; }

NTSTATUS
FwpsFlowRemoveContext0(_In_ uint64_t flow_id, _In_ UINT16 layer_id, _In_ uint32_t callout_id)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS

FwpsFlowAssociateContext0(
    _In_ uint64_t flow_id, _In_ UINT16 layer_id, _In_ uint32_t callout_id, _In_ uint64_t flowContext)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpsAllocateNetBufferAndNetBufferList0(
    _In_ NDIS_HANDLE pool_handle,
    _In_ uint16_t context_size,
    _In_ uint16_t context_backfill,
    _In_opt_ MDL* mdl_chain,
    _In_ unsigned long data_offset,
    _In_ size_t data_length,
    _Outptr_ NET_BUFFER_LIST** net_buffer_list)
{
    return STATUS_NO_MEMORY;
}

void
FwpsFreeNetBufferList0(_In_ NET_BUFFER_LIST* net_buffer_list)
{
    return;
}

NTSTATUS
FwpsInjectMacReceiveAsync0(
    _In_ HANDLE injection_handle,
    _In_opt_ HANDLE injection_context,
    _In_ uint32_t flags,
    _In_ UINT16 layer_id,
    _In_ IF_INDEX interface_index,
    _In_ NDIS_PORT_NUMBER ndis_port_number,
    _Inout_ NET_BUFFER_LIST* net_buffer_lists,
    _In_ void* completion_function,
    _In_opt_ HANDLE completion_context)
{
    return STATUS_NO_MEMORY;
}

void
FwpsFreeCloneNetBufferList0(_In_ NET_BUFFER_LIST* net_buffer_list, _In_ unsigned long free_clone_flags)
{
    return;
}

NTSTATUS
FwpsAllocateCloneNetBufferList0(
    _Inout_ NET_BUFFER_LIST* original_net_buffer_list,
    _In_opt_ NDIS_HANDLE net_buffer_list_pool_handle,
    _In_opt_ NDIS_HANDLE net_buffer_pool_handle,
    _In_ unsigned long allocate_clone_flags,
    _Outptr_ NET_BUFFER_LIST** net_buffer_list)
{
    return STATUS_NO_MEMORY;
}

NTSTATUS
FwpsInjectMacSendAsync0(
    _In_ HANDLE injection_handle,
    _In_opt_ HANDLE injection_context,
    _In_ uint32_t flags,
    _In_ UINT16 layer_id,
    _In_ IF_INDEX interface_index,
    _In_ NDIS_PORT_NUMBER ndis_port_number,
    _Inout_ NET_BUFFER_LIST* net_buffer_lists,
    _In_ void* completion_function,
    _In_opt_ HANDLE completion_context)
{
    return STATUS_NO_MEMORY;
}