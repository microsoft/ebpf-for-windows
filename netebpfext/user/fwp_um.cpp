// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "fwp_um.h"

std::unique_ptr<_fwp_engine> _fwp_engine::_engine;

// Attempt to classify a test packet at a given WFP layer on a given interface index.
FWP_ACTION_TYPE
_fwp_engine::classify_test_packet(_In_ const GUID* layer_guid, NET_IFINDEX if_index)
{
    std::unique_lock l(lock);
    const GUID* callout_key = get_callout_key_from_layer_guid(layer_guid);
    if (callout_key == nullptr) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }
    const FWPS_CALLOUT3* callout = get_callout_from_key(callout_key);
    if (callout == nullptr) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }
    FWPS_CLASSIFY_OUT0 result = {};
    FWPS_INCOMING_VALUE0 incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_MAX] = {};
    FWPS_INCOMING_VALUES incoming_fixed_values = {.incomingValue = incomingValue};
    incoming_fixed_values.incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_INDEX].value.uint32 = if_index;
    FWPS_INCOMING_METADATA_VALUES incoming_metadata_values = {};
    const FWPM_FILTER* fwpm_filter = get_fwpm_filter_with_context();
    if (!fwpm_filter) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }
    FWPS_FILTER fwps_filter = {.context = fwpm_filter->rawContext};
    NET_BUFFER_LIST_POOL_PARAMETERS pool_parameters = {};
    std::unique_ptr<void, decltype(&NdisFreeNetBufferListPool)> nbl_pool_handle(
        NdisAllocateNetBufferListPool(nullptr, &pool_parameters), NdisFreeNetBufferListPool);
    if (!nbl_pool_handle) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }

    std::unique_ptr<NET_BUFFER_LIST, decltype(&NdisFreeNetBufferList)> nbl(
        NdisAllocateNetBufferList(nbl_pool_handle.get(), 0, 0), NdisFreeNetBufferList);
    if (!nbl) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }

    ULONG data = 0;
    std::unique_ptr<MDL, decltype(&IoFreeMdl)> mdl_chain(
        IoAllocateMdl(&data, sizeof(data), FALSE, FALSE, nullptr), IoFreeMdl);
    if (!mdl_chain) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }

    std::unique_ptr<NET_BUFFER, decltype(&NdisFreeNetBuffer)> nb(
        NdisAllocateNetBuffer(nbl_pool_handle.get(), mdl_chain.get(), 0, sizeof(data)), NdisFreeNetBuffer);
    if (!nb) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }

    nbl->FirstNetBuffer = nb.get();
    callout->classifyFn(
        &incoming_fixed_values,
        &incoming_metadata_values,
        nbl.get(),
        nullptr, // classifyContext,
        &fwps_filter,
        0, // flowContext,
        &result);

    return result.actionType;
}

void
_fwp_engine::test_bind()
{
    // TODO(issue #1869): implement bind callout.
}

void
_fwp_engine::test_cgroup_sock_addr()
{
    // TODO(issue #1869): implement sock_addr callout.
}

void
_fwp_engine::test_sock_ops()
{
    // TODO(issue #1869): implement sock_ops callout.
}

typedef struct _fwp_injection_handle
{
    ADDRESS_FAMILY address_family;
    uint32_t flags;
} fwp_injection_handle;

static std::unique_ptr<fwp_injection_handle> _injection_handle;

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmFilterDeleteById0(_In_ HANDLE engine_handle, _In_ uint64_t id)
{
    auto& engine = *reinterpret_cast<_fwp_engine*>(engine_handle);

    if (engine.remove_fwpm_filter(id)) {
        return STATUS_SUCCESS;
    } else {
        return STATUS_INVALID_PARAMETER;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    FwpmTransactionBegin0(_In_ _Acquires_lock_(_Curr_) HANDLE engine_handle, _In_ uint32_t flags)
{
    UNREFERENCED_PARAMETER(engine_handle);
    UNREFERENCED_PARAMETER(flags);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmFilterAdd0(
    _In_ HANDLE engine_handle,
    _In_ const FWPM_FILTER0* filter,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ uint64_t* id)
{
    UNREFERENCED_PARAMETER(sd);

    auto& engine = *reinterpret_cast<_fwp_engine*>(engine_handle);

    auto id_returned = engine.add_fwpm_filter(filter);

    if (id) {
        *id = id_returned;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmTransactionCommit0(_In_ _Releases_lock_(_Curr_) HANDLE engine_handle)
{
    UNREFERENCED_PARAMETER(engine_handle);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmTransactionAbort0(_In_ _Releases_lock_(_Curr_) HANDLE engine_handle)
{
    UNREFERENCED_PARAMETER(engine_handle);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    FwpsCalloutRegister3(_Inout_ void* device_object, _In_ const FWPS_CALLOUT3* callout, _Out_opt_ uint32_t* callout_id)
{
    UNREFERENCED_PARAMETER(device_object);

    auto& engine = *_fwp_engine::get()->get();

    auto id_returned = engine.register_fwps_callout(callout);

    if (callout_id) {
        *callout_id = id_returned;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmCalloutAdd0(
    _In_ HANDLE engine_handle,
    _In_ const FWPM_CALLOUT0* callout,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ uint32_t* id)
{
    auto& engine = *reinterpret_cast<_fwp_engine*>(engine_handle);

    auto id_returned = engine.add_fwpm_callout(callout);

    if (id) {
        *id = id_returned;
    }
    UNREFERENCED_PARAMETER(sd);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpsCalloutUnregisterById0(_In_ const uint32_t callout_id)
{
    auto& engine = *_fwp_engine::get()->get();

    if (engine.remove_fwps_callout(callout_id)) {
        return STATUS_SUCCESS;
    } else {
        return STATUS_INVALID_PARAMETER;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmEngineOpen0(
    _In_opt_ const wchar_t* server_name,
    _In_ uint32_t authn_service,
    _In_opt_ SEC_WINNT_AUTH_IDENTITY_W* auth_identity,
    _In_opt_ const FWPM_SESSION0* session,
    _Out_ HANDLE* engine_handle)
{
    UNREFERENCED_PARAMETER(server_name);
    UNREFERENCED_PARAMETER(authn_service);
    UNREFERENCED_PARAMETER(auth_identity);
    UNREFERENCED_PARAMETER(session);

    *engine_handle = _fwp_engine::get()->get();
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    FwpmSubLayerAdd0(_In_ HANDLE engine_handle, _In_ const FWPM_SUBLAYER0* sub_layer, _In_opt_ PSECURITY_DESCRIPTOR sd)
{
    UNREFERENCED_PARAMETER(sd);
    auto& engine = *reinterpret_cast<_fwp_engine*>(engine_handle);

    engine.add_fwpm_sub_layer(sub_layer);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmEngineClose0(_Inout_ HANDLE engine_handle)
{
    if (engine_handle != _fwp_engine::get()->get()) {
        return STATUS_INVALID_PARAMETER;
    } else {
        return STATUS_SUCCESS;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpsInjectionHandleCreate0(
    _In_opt_ ADDRESS_FAMILY address_family, _In_ uint32_t flags, _Out_ HANDLE* injection_handle)
{
    _injection_handle = std::make_unique<_fwp_injection_handle>(address_family, flags);
    *injection_handle = _injection_handle.get();

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpsInjectionHandleDestroy0(_In_ HANDLE injection_handle)
{
    if (injection_handle != _injection_handle.get()) {
        return STATUS_INVALID_PARAMETER;
    } else {
        _injection_handle.reset();
        return STATUS_SUCCESS;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS
    FwpsFlowRemoveContext0(_In_ uint64_t flow_id, _In_ UINT16 layer_id, _In_ uint32_t callout_id)
{
    UNREFERENCED_PARAMETER(flow_id);
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);
    return STATUS_NOT_IMPLEMENTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS FwpsFlowAssociateContext0(
    _In_ uint64_t flow_id, _In_ UINT16 layer_id, _In_ uint32_t callout_id, _In_ uint64_t flowContext)
{
    UNREFERENCED_PARAMETER(flow_id);
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);
    UNREFERENCED_PARAMETER(flowContext);
    return STATUS_NOT_IMPLEMENTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS FwpsAllocateNetBufferAndNetBufferList0(
    _In_ NDIS_HANDLE pool_handle,
    _In_ uint16_t context_size,
    _In_ uint16_t context_backfill,
    _In_opt_ MDL* mdl_chain,
    _In_ unsigned long data_offset,
    _In_ size_t data_length,
    _Outptr_ NET_BUFFER_LIST** net_buffer_list)
{
    NTSTATUS status;
    NET_BUFFER_LIST* new_net_buffer_list = NULL;

    UNREFERENCED_PARAMETER(pool_handle);
    UNREFERENCED_PARAMETER(context_size);
    UNREFERENCED_PARAMETER(context_backfill);
    UNREFERENCED_PARAMETER(data_offset);

    new_net_buffer_list =
        (NET_BUFFER_LIST*)(ExAllocatePoolUninitialized(NonPagedPool, sizeof(NET_BUFFER_LIST), '1PWF'));
    if (!new_net_buffer_list) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    RtlZeroMemory(new_net_buffer_list, sizeof(NET_BUFFER_LIST));

    new_net_buffer_list->FirstNetBuffer =
        (NET_BUFFER*)(ExAllocatePoolUninitialized(NonPagedPool, sizeof(NET_BUFFER), '2PWF'));
    if (!new_net_buffer_list->FirstNetBuffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    RtlZeroMemory(new_net_buffer_list->FirstNetBuffer, sizeof(NET_BUFFER));

    new_net_buffer_list->FirstNetBuffer->MdlChain = mdl_chain;
    new_net_buffer_list->FirstNetBuffer->DataLength = (unsigned long)data_length;

    *net_buffer_list = new_net_buffer_list;
    new_net_buffer_list = NULL;
    status = STATUS_SUCCESS;

Done:
    if (new_net_buffer_list) {
        FwpsFreeNetBufferList0(new_net_buffer_list);
    }
    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL) void FwpsFreeNetBufferList0(_In_ NET_BUFFER_LIST* net_buffer_list)
{
    if (!net_buffer_list) {
        return;
    }

    if (net_buffer_list->FirstNetBuffer) {
        ExFreePool(net_buffer_list->FirstNetBuffer);
    }

    ExFreePool(net_buffer_list);
}

_IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_max_(DISPATCH_LEVEL) _Must_inspect_result_ NTSTATUS
    FwpsInjectMacReceiveAsync0(
        _In_ HANDLE injection_handle,
        _In_opt_ HANDLE injection_context,
        _In_ uint32_t flags,
        _In_ UINT16 layer_id,
        _In_ IF_INDEX interface_index,
        _In_ NDIS_PORT_NUMBER ndis_port_number,
        _Inout_ NET_BUFFER_LIST* net_buffer_lists,
        _In_ FWPS_INJECT_COMPLETE completion_function,
        _In_opt_ HANDLE completion_context)
{
    UNREFERENCED_PARAMETER(injection_handle);
    UNREFERENCED_PARAMETER(injection_context);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(interface_index);
    UNREFERENCED_PARAMETER(ndis_port_number);
    UNREFERENCED_PARAMETER(net_buffer_lists);
    UNREFERENCED_PARAMETER(completion_function);
    UNREFERENCED_PARAMETER(completion_context);
    return STATUS_NOT_IMPLEMENTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL) void FwpsFreeCloneNetBufferList0(
    _In_ NET_BUFFER_LIST* net_buffer_list, _In_ unsigned long free_clone_flags)
{
    UNREFERENCED_PARAMETER(net_buffer_list);
    UNREFERENCED_PARAMETER(free_clone_flags);
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS FwpsAllocateCloneNetBufferList0(
    _Inout_ NET_BUFFER_LIST* original_net_buffer_list,
    _In_opt_ NDIS_HANDLE net_buffer_list_pool_handle,
    _In_opt_ NDIS_HANDLE net_buffer_pool_handle,
    _In_ unsigned long allocate_clone_flags,
    _Outptr_ NET_BUFFER_LIST** net_buffer_list)
{
    UNREFERENCED_PARAMETER(original_net_buffer_list);
    UNREFERENCED_PARAMETER(net_buffer_list_pool_handle);
    UNREFERENCED_PARAMETER(net_buffer_pool_handle);
    UNREFERENCED_PARAMETER(net_buffer_pool_handle);
    UNREFERENCED_PARAMETER(allocate_clone_flags);
    UNREFERENCED_PARAMETER(net_buffer_list);
    return STATUS_NOT_IMPLEMENTED;
}

_IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_max_(DISPATCH_LEVEL) _Must_inspect_result_ NTSTATUS
    FwpsInjectMacSendAsync0(
        _In_ HANDLE injection_handle,
        _In_opt_ HANDLE injection_context,
        _In_ uint32_t flags,
        _In_ UINT16 layer_id,
        _In_ IF_INDEX interface_index,
        _In_ NDIS_PORT_NUMBER ndis_port_number,
        _Inout_ NET_BUFFER_LIST* net_buffer_lists,
        _In_ FWPS_INJECT_COMPLETE completion_function,
        _In_opt_ HANDLE completion_context)
{
    UNREFERENCED_PARAMETER(injection_handle);
    UNREFERENCED_PARAMETER(injection_context);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(interface_index);
    UNREFERENCED_PARAMETER(ndis_port_number);
    UNREFERENCED_PARAMETER(net_buffer_lists);
    UNREFERENCED_PARAMETER(completion_function);
    UNREFERENCED_PARAMETER(completion_context);
    return STATUS_NOT_IMPLEMENTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS NTAPI FwpsAcquireWritableLayerDataPointer0(
    _In_ UINT64 classifyHandle,
    _In_ UINT64 filterId,
    _In_ UINT32 flags,
    _Out_ PVOID* writableLayerData,
    _Inout_opt_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(classifyHandle);
    UNREFERENCED_PARAMETER(filterId);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(classifyOut);

    *writableLayerData = NULL;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS NTAPI
    FwpsAcquireClassifyHandle0(_In_ void* classifyContext, _In_ UINT32 flags, _Out_ UINT64* classifyHandle)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(classifyHandle);

    *classifyHandle = 0;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL) void NTAPI FwpsReleaseClassifyHandle0(_In_ UINT64 classifyHandle)
{
    UNREFERENCED_PARAMETER(classifyHandle);
}

_IRQL_requires_max_(DISPATCH_LEVEL) void NTAPI
    FwpsApplyModifiedLayerData0(_In_ UINT64 classifyHandle, _In_ PVOID modifiedLayerData, _In_ UINT32 flags)
{
    UNREFERENCED_PARAMETER(classifyHandle);
    UNREFERENCED_PARAMETER(modifiedLayerData);
    UNREFERENCED_PARAMETER(flags);
}

_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS NTAPI
    FwpsRedirectHandleCreate0(_In_ const GUID* providerGuid, _Reserved_ UINT32 flags, _Out_ HANDLE* redirectHandle)
{
    UNREFERENCED_PARAMETER(providerGuid);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(redirectHandle);

    *redirectHandle = 0;

    return STATUS_SUCCESS;
}

_IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_max_(DISPATCH_LEVEL) FWPS_CONNECTION_REDIRECT_STATE NTAPI
    FwpsQueryConnectionRedirectState0(
        _In_ HANDLE redirectRecords, _In_ HANDLE redirectHandle, _Outptr_opt_result_maybenull_ void** redirectContext)
{
    UNREFERENCED_PARAMETER(redirectRecords);
    UNREFERENCED_PARAMETER(redirectHandle);

    if (redirectContext) {
        *redirectContext = NULL;
    }

    return FWPS_CONNECTION_NOT_REDIRECTED;
}