// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/*++

Abstract:

   This file implements the classifyFn, notifiFn, and flowDeleteFn callouts
   functions for:
   Layer 2 network receive
   Resource Acquire
   Resource Release

Environment:

    Kernel mode

--*/

#include "net_ebpf_ext.h"
#include "net_ebpf_ext_bind.h"
#include "net_ebpf_ext_sock_addr.h"
#include "net_ebpf_ext_xdp.h"

// Globals.
NDIS_HANDLE _net_ebpf_ext_ndis_handle = NULL;
NDIS_HANDLE _net_ebpf_ext_nbl_pool_handle = NULL;
HANDLE _net_ebpf_ext_l2_injection_handle = NULL;

static void
_net_ebpf_ext_flow_delete(uint16_t layer_id, uint32_t fwpm_callout_id, uint64_t flow_context);

static NTSTATUS
_net_ebpf_ext_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ const FWPS_FILTER* filter);

typedef struct _net_ebpf_ext_wfp_callout_state
{
    const GUID* callout_guid;
    const GUID* layer_guid;
    FWPS_CALLOUT_CLASSIFY_FN classify_fn;
    FWPS_CALLOUT_NOTIFY_FN notify_fn;
    FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN delete_fn;
    wchar_t* name;
    wchar_t* description;
    FWP_ACTION_TYPE filter_action_type;
    uint32_t assigned_callout_id;
} net_ebpf_ext_wfp_callout_state_t;

static net_ebpf_ext_wfp_callout_state_t _net_ebpf_ext_wfp_callout_state[] = {
    {
        &EBPF_HOOK_OUTBOUND_L2_CALLOUT,
        &FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
        net_ebpf_ext_layer_2_classify,
        _net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"L2 Outbound",
        L"L2 Outbound Callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_INBOUND_L2_CALLOUT,
        &FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
        net_ebpf_ext_layer_2_classify,
        _net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"L2 Inbound",
        L"L2 Inbound Callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_ALE_RESOURCE_ALLOC_V4_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        net_ebpf_ext_resource_allocation_classify,
        _net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Allocation v4",
        L"Resource Allocation v4 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_ALE_RESOURCE_RELEASE_V4_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_RELEASE_V4,
        net_ebpf_ext_resource_release_classify,
        _net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Release v4",
        L"Resource Release v4 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_ALE_RESOURCE_ALLOC_V6_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
        net_ebpf_ext_resource_allocation_classify,
        _net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Allocation v6",
        L"Resource Allocation v6 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_ALE_RESOURCE_RELEASE_V6_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_RELEASE_V6,
        net_ebpf_ext_resource_release_classify,
        _net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Release eBPF Callout v6",
        L"Resource Release callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_ALE_AUTH_CONNECT_V4_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        net_ebpf_extension_sock_addr_authorize_connection_classify,
        _net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Connect eBPF Callout v4",
        L"ALE Authorize Connect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_ALE_AUTH_CONNECT_V6_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        net_ebpf_extension_sock_addr_authorize_connection_classify,
        _net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Connect eBPF Callout v6",
        L"ALE Authorize Connect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        net_ebpf_extension_sock_addr_authorize_connection_classify,
        _net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Receive or Accept eBPF Callout v4",
        L"ALE Authorize Receive or Accept callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        net_ebpf_extension_sock_addr_authorize_connection_classify,
        _net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Receive or Accept eBPF Callout v6",
        L"ALE Authorize Receive or Accept callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    }};

// WFP globals
static HANDLE _fwp_engine_handle;

//
// WFP component management related utility functions.
//

void
net_ebpf_extension_delete_wfp_filters(uint32_t filter_count, _In_count_(filter_count) uint64_t* filter_ids)
{
    for (uint32_t index = 0; index < filter_count; index++)
        FwpmFilterDeleteById(_fwp_engine_handle, filter_ids[index]);
}

ebpf_result_t
net_ebpf_extension_add_wfp_filters(
    uint32_t filter_count,
    _In_count_(filter_count) const net_ebpf_extension_wfp_filter_parameters_t* parameters,
    uint32_t condition_count,
    _In_opt_count_(condition_count) const FWPM_FILTER_CONDITION* conditions,
    _In_ const void* raw_context,
    _Out_writes_(filter_count) uint64_t* filter_ids)
{
    NTSTATUS status = STATUS_SUCCESS;
    ebpf_result_t result = EBPF_SUCCESS;
    BOOL is_in_transaction = FALSE;

    status = FwpmTransactionBegin(_fwp_engine_handle, 0);
    if (!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "NetEbpfExt: FwpmTransactionBegin failed with error %.2X\n",
             status));
        goto Exit;
    }
    is_in_transaction = TRUE;

    for (uint32_t index = 0; index < filter_count; index++) {
        FWPM_FILTER filter = {0};
        const net_ebpf_extension_wfp_filter_parameters_t* filter_parameter = &parameters[index];

        filter.layerKey = *filter_parameter->layer_guid;
        filter.displayData.name = (wchar_t*)filter_parameter->name;
        filter.displayData.description = (wchar_t*)filter_parameter->description;
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = *filter_parameter->callout_guid;
        filter.filterCondition = (FWPM_FILTER_CONDITION*)conditions;
        filter.numFilterConditions = condition_count;
        filter.subLayerKey = EBPF_SUBLAYER;
        filter.weight.type = FWP_EMPTY; // auto-weight.
        filter.rawContext = (uint64_t)(uintptr_t)raw_context;

        status = FwpmFilterAdd(_fwp_engine_handle, &filter, NULL, &filter_ids[index]);

        if (!NT_SUCCESS(status)) {
            KdPrintEx(
                (DPFLTR_IHVDRIVER_ID,
                 DPFLTR_INFO_LEVEL,
                 "NetEbpfExt: FwpmFilterAdd for %S failed with error %.2X\n",
                 filter_parameter->name,
                 status));
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
    }

    status = FwpmTransactionCommit(_fwp_engine_handle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "NetEbpfExt: FwpmTransactionCommit failed with error %.2X\n",
             status));
        goto Exit;
    }
    is_in_transaction = FALSE;

Exit:
    if (!NT_SUCCESS(status)) {
        if (is_in_transaction)
            FwpmTransactionAbort(_fwp_engine_handle);
    }

    return result;
}

static NTSTATUS
_net_ebpf_ext_register_wfp_callout(_Inout_ net_ebpf_ext_wfp_callout_state_t* callout_state, _Inout_ void* device_object)
/* ++

   This function registers callouts and filters.

-- */
{
    NTSTATUS status = STATUS_SUCCESS;

    FWPS_CALLOUT callout_register_state = {0};
    FWPM_CALLOUT callout_add_state = {0};

    FWPM_DISPLAY_DATA display_data = {0};

    BOOLEAN was_callout_registered = FALSE;

    callout_register_state.calloutKey = *callout_state->callout_guid;
    callout_register_state.classifyFn = callout_state->classify_fn;
    callout_register_state.notifyFn = callout_state->notify_fn;
    callout_register_state.flowDeleteFn = callout_state->delete_fn;
    callout_register_state.flags = 0;

    status = FwpsCalloutRegister(device_object, &callout_register_state, &callout_state->assigned_callout_id);
    if (!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "NetEbpfExt: FwpsCalloutRegister for %S failed with error %.2X\n",
             callout_state->name,
             status));
        goto Exit;
    }
    was_callout_registered = TRUE;

    display_data.name = callout_state->name;
    display_data.description = callout_state->description;

    callout_add_state.calloutKey = *callout_state->callout_guid;
    callout_add_state.displayData = display_data;
    callout_add_state.applicableLayer = *callout_state->layer_guid;

    status = FwpmCalloutAdd(_fwp_engine_handle, &callout_add_state, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "NetEbpfExt: FwpmCalloutAdd for %S failed with error %.2X\n",
             callout_state->name,
             status));
        goto Exit;
    }

Exit:

    if (!NT_SUCCESS(status)) {
        if (was_callout_registered) {
            FwpsCalloutUnregisterById(callout_state->assigned_callout_id);
            callout_state->assigned_callout_id = 0;
        }
    }

    return status;
}

NTSTATUS
net_ebpf_ext_initialize_ndis_handles(_In_ const DRIVER_OBJECT* driver_object)
{
    NTSTATUS status = STATUS_SUCCESS;
    NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_parameters = {0};

    _net_ebpf_ext_ndis_handle =
        NdisAllocateGenericObject((DRIVER_OBJECT*)driver_object, NET_EBPF_EXTENSION_POOL_TAG, 0);
    if (_net_ebpf_ext_ndis_handle == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    nbl_pool_parameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbl_pool_parameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nbl_pool_parameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nbl_pool_parameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    nbl_pool_parameters.fAllocateNetBuffer = TRUE;
    nbl_pool_parameters.DataSize = 0;
    nbl_pool_parameters.PoolTag = NET_EBPF_EXTENSION_POOL_TAG;

    _net_ebpf_ext_nbl_pool_handle = NdisAllocateNetBufferListPool(_net_ebpf_ext_ndis_handle, &nbl_pool_parameters);
    if (_net_ebpf_ext_nbl_pool_handle == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

Exit:
    return status;
}

void
net_ebpf_ext_uninitialize_ndis_handles()
{
    if (_net_ebpf_ext_nbl_pool_handle != NULL)
        NdisFreeNetBufferListPool(_net_ebpf_ext_nbl_pool_handle);

    if (_net_ebpf_ext_ndis_handle != NULL)
        NdisFreeGenericObject(_net_ebpf_ext_ndis_handle);
}

NTSTATUS
net_ebpf_extension_initialize_wfp_components(_Inout_ void* device_object)
/* ++

   This function initializes various WFP related components.

-- */
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SUBLAYER ebpf_hook_sub_layer;

    BOOLEAN is_engined_opened = FALSE;
    BOOLEAN is_in_transaction = FALSE;

    FWPM_SESSION session = {0};

    size_t index;

    if (_fwp_engine_handle != NULL) {
        // already registered
        goto Exit;
    }

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &_fwp_engine_handle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "NetEbpfExt: FwpmEngineOpen failed with error %.2X\n", status));
        goto Exit;
    }
    is_engined_opened = TRUE;

    status = FwpmTransactionBegin(_fwp_engine_handle, 0);
    if (!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "NetEbpfExt: FwpmTransactionBegin failed with error %.2X\n",
             status));
        goto Exit;
    }
    is_in_transaction = TRUE;

    RtlZeroMemory(&ebpf_hook_sub_layer, sizeof(FWPM_SUBLAYER));

    ebpf_hook_sub_layer.subLayerKey = EBPF_SUBLAYER;
    ebpf_hook_sub_layer.displayData.name = L"EBPF Sub-Layer";
    ebpf_hook_sub_layer.displayData.description = L"Sub-Layer for use by EBPF callouts";
    ebpf_hook_sub_layer.flags = 0;
    ebpf_hook_sub_layer.weight = FWP_EMPTY; // auto-weight.;

    status = FwpmSubLayerAdd(_fwp_engine_handle, &ebpf_hook_sub_layer, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "NetEbpfExt: FwpmSubLayerAdd failed with error %.2X\n", status));
        goto Exit;
    }

    for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_state); index++) {
        status = _net_ebpf_ext_register_wfp_callout(&_net_ebpf_ext_wfp_callout_state[index], device_object);
        if (!NT_SUCCESS(status)) {
            KdPrintEx(
                (DPFLTR_IHVDRIVER_ID,
                 DPFLTR_INFO_LEVEL,
                 "NetEbpfExt: _net_ebpf_ext_register_wfp_callout failed for %S with "
                 "error %.2X\n",
                 _net_ebpf_ext_wfp_callout_state[index].name,
                 status));
            goto Exit;
        }
    }

    status = FwpmTransactionCommit(_fwp_engine_handle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "NetEbpfExt: FwpmTransactionCommit failed with error %.2X\n",
             status));
        goto Exit;
    }
    is_in_transaction = FALSE;

    // Create L2 injection handle.
    status = FwpsInjectionHandleCreate(AF_LINK, FWPS_INJECTION_TYPE_L2, &_net_ebpf_ext_l2_injection_handle);
    if (!NT_SUCCESS(status))
        goto Exit;

Exit:

    if (!NT_SUCCESS(status)) {
        if (is_in_transaction) {
            FwpmTransactionAbort(_fwp_engine_handle);
        }
    }

    return status;
}

void
net_ebpf_extension_uninitialize_wfp_components(void)
{
    size_t index;
    if (_fwp_engine_handle != NULL) {
        FwpmEngineClose(_fwp_engine_handle);
        _fwp_engine_handle = NULL;

        for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_state); index++) {
            FwpsCalloutUnregisterById(_net_ebpf_ext_wfp_callout_state[index].assigned_callout_id);
        }
    }

    FwpsInjectionHandleDestroy(_net_ebpf_ext_l2_injection_handle);
}

static NTSTATUS
_net_ebpf_ext_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ const FWPS_FILTER* filter)
{
    UNREFERENCED_PARAMETER(callout_notification_type);
    UNREFERENCED_PARAMETER(filter_key);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

static void
_net_ebpf_ext_flow_delete(uint16_t layer_id, uint32_t fwpm_callout_id, uint64_t flow_context)
/* ++

   This is the flowDeleteFn function of the L2 callout.

-- */
{
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(fwpm_callout_id);
    UNREFERENCED_PARAMETER(flow_context);
    return;
}

NTSTATUS
net_ebpf_ext_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    status = net_ebpf_ext_xdp_register_providers();
    if (status != STATUS_SUCCESS)
        goto Exit;

    status = net_ebpf_ext_bind_register_providers();
    if (status != STATUS_SUCCESS)
        goto Exit;

    status = net_ebpf_ext_sock_addr_register_providers();
    if (status != STATUS_SUCCESS)
        goto Exit;

Exit:
    return status;
}

void
net_ebpf_ext_unregister_providers()
{
    net_ebpf_ext_xdp_unregister_providers();
    net_ebpf_ext_bind_unregister_providers();
    net_ebpf_ext_sock_addr_unregister_providers();
}