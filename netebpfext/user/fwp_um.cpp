// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <unordered_map>
#include <mutex>

#include "netebpfext_platform.h"

typedef class _fwp_engine
{
  public:
    _fwp_engine() = default;

    uint32_t
    add_fwpm_callout(const FWPM_CALLOUT0* callout)
    {
        std::unique_lock l(lock);
        uint32_t id = next_id++;
        fwpm_callouts.insert({id, *callout});
        return id;
    }

    bool
    remove_fwpm_callout(size_t id)
    {
        std::unique_lock l(lock);
        return fwpm_callouts.erase(id) == 1;
    }

    uint32_t
    add_fwps_callout(const FWPS_CALLOUT3* callout)
    {
        std::unique_lock l(lock);
        uint32_t id = next_id++;
        fwps_callouts.insert({id, *callout});
        return id;
    }

    bool
    remove_fwps_callout(size_t id)
    {
        std::unique_lock l(lock);
        return fwps_callouts.erase(id) == 1;
    }

    uint32_t
    add_fwpm_filter(const FWPM_FILTER0* filter)
    {
        std::unique_lock l(lock);
        uint32_t id = next_id++;
        fwpm_filters.insert({id, *filter});
        return id;
    }

    bool
    remove_fwpm_filter(size_t id)
    {
        std::unique_lock l(lock);
        return fwpm_filters.erase(id) == 1;
    }

    uint32_t
    add_fwpm_sub_layer(const FWPM_SUBLAYER0* sub_layer)
    {
        std::unique_lock l(lock);
        uint32_t id = next_id++;
        fwpm_sub_layers.insert({id, *sub_layer});
        return id;
    }

    bool
    remove_fwpm_sub_layer(size_t id)
    {
        std::unique_lock l(lock);
        return fwpm_sub_layers.erase(id) == 1;
    }

  private:
    std::mutex lock;
    uint32_t next_id = 1;
    std::unordered_map<size_t, FWPS_CALLOUT3> fwps_callouts;
    std::unordered_map<size_t, FWPM_CALLOUT0> fwpm_callouts;
    std::unordered_map<size_t, FWPM_FILTER0> fwpm_filters;
    std::unordered_map<size_t, FWPM_SUBLAYER0> fwpm_sub_layers;
} fwp_engine;

static std::unique_ptr<fwp_engine> _engine;

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

    auto& engine = *_engine.get();

    auto id_returned = engine.add_fwps_callout(callout);

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
    auto& engine = *_engine.get();

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

    if (!_engine)
        _engine = std::make_unique<_fwp_engine>();

    *engine_handle = _engine.get();
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
    if (engine_handle != _engine.get()) {
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
    UNREFERENCED_PARAMETER(pool_handle);
    UNREFERENCED_PARAMETER(context_size);
    UNREFERENCED_PARAMETER(context_backfill);
    UNREFERENCED_PARAMETER(mdl_chain);
    UNREFERENCED_PARAMETER(data_offset);
    UNREFERENCED_PARAMETER(data_length);
    UNREFERENCED_PARAMETER(net_buffer_list);
    return STATUS_NOT_IMPLEMENTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL) void FwpsFreeNetBufferList0(_In_ NET_BUFFER_LIST* net_buffer_list)
{
    UNREFERENCED_PARAMETER(net_buffer_list);
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