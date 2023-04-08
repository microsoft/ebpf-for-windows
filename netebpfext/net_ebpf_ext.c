// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/*++

Abstract:

   This file implements the classifyFn, notifyFn, and flowDeleteFn callouts
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
#include "net_ebpf_ext_sock_ops.h"
#include "net_ebpf_ext_xdp.h"

// Globals.
NDIS_HANDLE _net_ebpf_ext_ndis_handle = NULL;
NDIS_HANDLE _net_ebpf_ext_nbl_pool_handle = NULL;
HANDLE _net_ebpf_ext_l2_injection_handle = NULL;

static bool _net_ebpf_xdp_providers_registered = false;
static bool _net_ebpf_bind_providers_registered = false;
static bool _net_ebpf_sock_addr_providers_registered = false;
static bool _net_ebpf_sock_ops_providers_registered = false;

static net_ebpf_ext_sublayer_info_t _net_ebpf_ext_sublayers[] = {
    {
        &EBPF_DEFAULT_SUBLAYER,
        L"EBPF Sub-Layer",
        L"Sub-Layer for use by eBPF callouts",
        0,
        FWP_EMPTY // Auto weight.
    },
    {
        &EBPF_HOOK_CGROUP_CONNECT_V4_SUBLAYER,
        L"EBPF CGroup Connect V4 Sub-Layer",
        L"Sub-Layer for use by eBPF connect redirect callouts",
        0,
        FWP_EMPTY // Auto weight.
    },
    {
        &EBPF_HOOK_CGROUP_CONNECT_V6_SUBLAYER,
        L"EBPF CGroup Connect V6 Sub-Layer",
        L"Sub-Layer for use by eBPF connect redirect callouts",
        0,
        FWP_EMPTY // Auto weight.
    }};

static void
_net_ebpf_ext_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context);

NTSTATUS
net_ebpf_ext_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ FWPS_FILTER* filter);

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

static net_ebpf_ext_wfp_callout_state_t _net_ebpf_ext_wfp_callout_states[] = {
    // EBPF_HOOK_OUTBOUND_L2
    {
        &EBPF_HOOK_OUTBOUND_L2_CALLOUT,
        &FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
        net_ebpf_ext_layer_2_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"L2 Outbound",
        L"L2 Outbound Callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_INBOUND_L2
    {
        &EBPF_HOOK_INBOUND_L2_CALLOUT,
        &FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
        net_ebpf_ext_layer_2_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"L2 Inbound",
        L"L2 Inbound Callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_ALLOC_V4
    {
        &EBPF_HOOK_ALE_RESOURCE_ALLOC_V4_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        net_ebpf_ext_resource_allocation_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Allocation v4",
        L"Resource Allocation v4 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_RELEASE_V4
    {
        &EBPF_HOOK_ALE_RESOURCE_RELEASE_V4_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_RELEASE_V4,
        net_ebpf_ext_resource_release_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Release v4",
        L"Resource Release v4 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_ALLOC_V6
    {
        &EBPF_HOOK_ALE_RESOURCE_ALLOC_V6_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
        net_ebpf_ext_resource_allocation_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Allocation v6",
        L"Resource Allocation v6 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_RELEASE_V6
    {
        &EBPF_HOOK_ALE_RESOURCE_RELEASE_V6_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_RELEASE_V6,
        net_ebpf_ext_resource_release_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Release eBPF Callout v6",
        L"Resource Release callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_CONNECT_V4
    {
        &EBPF_HOOK_ALE_AUTH_CONNECT_V4_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        net_ebpf_extension_sock_addr_authorize_connection_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Connect eBPF Callout v4",
        L"ALE Authorize Connect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_CONNECT_V6
    {
        &EBPF_HOOK_ALE_AUTH_CONNECT_V6_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        net_ebpf_extension_sock_addr_authorize_connection_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Connect eBPF Callout v6",
        L"ALE Authorize Connect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4
    {
        &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        net_ebpf_extension_sock_addr_authorize_recv_accept_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Receive or Accept eBPF Callout v4",
        L"ALE Authorize Receive or Accept callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6
    {
        &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        net_ebpf_extension_sock_addr_authorize_recv_accept_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Receive or Accept eBPF Callout v6",
        L"ALE Authorize Receive or Accept callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V4
    {
        &EBPF_HOOK_ALE_CONNECT_REDIRECT_V4_CALLOUT,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        net_ebpf_extension_sock_addr_redirect_connection_classify,
        net_ebpf_ext_connect_redirect_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Connect Redirect eBPF Callout v4",
        L"ALE Connect Redirect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V6
    {
        &EBPF_HOOK_ALE_CONNECT_REDIRECT_V6_CALLOUT,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        net_ebpf_extension_sock_addr_redirect_connection_classify,
        net_ebpf_ext_connect_redirect_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Connect Redirect eBPF Callout v6",
        L"ALE Connect Redirect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4
    {
        &EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4_CALLOUT,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        net_ebpf_extension_sock_ops_flow_established_classify,
        net_ebpf_ext_filter_change_notify,
        net_ebpf_extension_sock_ops_flow_delete,
        L"ALE Flow Established Callout v4",
        L"ALE Flow Established callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6
    {
        &EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6_CALLOUT,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
        net_ebpf_extension_sock_ops_flow_established_classify,
        net_ebpf_ext_filter_change_notify,
        net_ebpf_extension_sock_ops_flow_delete,
        L"ALE Flow Established Callout v4",
        L"ALE Flow Established callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    }};

// WFP globals
static HANDLE _fwp_engine_handle;

//
// WFP component management related utility functions.
//

_Must_inspect_result_ ebpf_result_t
net_ebpf_extension_wfp_filter_context_create(
    size_t filter_context_size,
    _In_ const net_ebpf_extension_hook_client_t* client_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    net_ebpf_extension_wfp_filter_context_t* local_filter_context = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    *filter_context = NULL;

    // Allocate buffer for WFP filter context.
    local_filter_context = (net_ebpf_extension_wfp_filter_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, filter_context_size, NET_EBPF_EXTENSION_POOL_TAG);
    if (local_filter_context == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(local_filter_context, 0, filter_context_size);
    local_filter_context->reference_count = 1; // Initial reference.
    local_filter_context->client_context = client_context;

    *filter_context = local_filter_context;
    local_filter_context = NULL;
Exit:
    if (local_filter_context != NULL) {
        ExFreePool(local_filter_context);
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

void
net_ebpf_extension_wfp_filter_context_cleanup(_Frees_ptr_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    // Since the hook client is detaching, the eBPF program should not be invoked any further.
    // The client_context field in filter_context is set to NULL for this reason. This way any
    // lingering WFP classify callbacks will exit as it would not find any hook client associated with the filter
    // context. This is best effort & no locks are held.
    filter_context->client_context = NULL;
    filter_context->filter_ids = NULL;
    filter_context->filter_ids_count = 0;
    DEREFERENCE_FILTER_CONTEXT(filter_context);
}

net_ebpf_extension_hook_id_t
net_ebpf_extension_get_hook_id_from_wfp_layer_id(uint16_t wfp_layer_id)
{
    net_ebpf_extension_hook_id_t hook_id = (net_ebpf_extension_hook_id_t)0;

    switch (wfp_layer_id) {
    case FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE:
        hook_id = EBPF_HOOK_OUTBOUND_L2;
        break;
    case FWPS_LAYER_INBOUND_MAC_FRAME_NATIVE:
        hook_id = EBPF_HOOK_INBOUND_L2;
        break;
    case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4:
        hook_id = EBPF_HOOK_ALE_RESOURCE_ALLOC_V4;
        break;
    case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6:
        hook_id = EBPF_HOOK_ALE_RESOURCE_ALLOC_V6;
        break;
    case FWPS_LAYER_ALE_RESOURCE_RELEASE_V4:
        hook_id = EBPF_HOOK_ALE_RESOURCE_RELEASE_V4;
        break;
    case FWPS_LAYER_ALE_RESOURCE_RELEASE_V6:
        hook_id = EBPF_HOOK_ALE_RESOURCE_RELEASE_V6;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        hook_id = EBPF_HOOK_ALE_AUTH_CONNECT_V4;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        hook_id = EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        hook_id = EBPF_HOOK_ALE_AUTH_CONNECT_V6;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        hook_id = EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6;
        break;
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
        hook_id = EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4;
        break;
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6:
        hook_id = EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6;
        break;
    case FWPS_LAYER_ALE_CONNECT_REDIRECT_V4:
        hook_id = EBPF_HOOK_ALE_CONNECT_REDIRECT_V4;
        break;
    case FWPS_LAYER_ALE_CONNECT_REDIRECT_V6:
        hook_id = EBPF_HOOK_ALE_CONNECT_REDIRECT_V6;
        break;
    default:
        ASSERT(FALSE);
        break;
    }

    return hook_id;
}

uint32_t
net_ebpf_extension_get_callout_id_for_hook(net_ebpf_extension_hook_id_t hook_id)
{
    uint32_t callout_id = 0;

    if (hook_id < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_states)) {
        callout_id = _net_ebpf_ext_wfp_callout_states[hook_id].assigned_callout_id;
    }

    return callout_id;
}
void
net_ebpf_extension_delete_wfp_filters(uint32_t filter_count, _Frees_ptr_ _In_count_(filter_count) uint64_t* filter_ids)
{
    NET_EBPF_EXT_LOG_ENTRY();
    for (uint32_t index = 0; index < filter_count; index++) {
        FwpmFilterDeleteById(_fwp_engine_handle, filter_ids[index]);
    }
    ExFreePool(filter_ids);
    NET_EBPF_EXT_LOG_EXIT();
}

_Must_inspect_result_ ebpf_result_t
net_ebpf_extension_add_wfp_filters(
    uint32_t filter_count,
    _In_count_(filter_count) const net_ebpf_extension_wfp_filter_parameters_t* parameters,
    uint32_t condition_count,
    _In_opt_count_(condition_count) const FWPM_FILTER_CONDITION* conditions,
    _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _Outptr_result_buffer_maybenull_(filter_count) uint64_t** filter_ids)
{
    NTSTATUS status = STATUS_SUCCESS;
    ebpf_result_t result = EBPF_SUCCESS;
    bool is_in_transaction = FALSE;
    uint64_t* local_filter_ids = NULL;
    *filter_ids = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    if (filter_count == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    local_filter_ids = (uint64_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(uint64_t) * filter_count, NET_EBPF_EXTENSION_POOL_TAG);
    if (local_filter_ids == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(local_filter_ids, 0, sizeof(uint64_t) * filter_count);

    status = FwpmTransactionBegin(_fwp_engine_handle, 0);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpmTransactionBegin", status);
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    is_in_transaction = TRUE;

    for (uint32_t index = 0; index < filter_count; index++) {
        FWPM_FILTER filter = {0};
        const net_ebpf_extension_wfp_filter_parameters_t* filter_parameter = &parameters[index];

        filter.layerKey = *filter_parameter->layer_guid;
        filter.displayData.name = (wchar_t*)filter_parameter->name;
        filter.displayData.description = (wchar_t*)filter_parameter->description;
        filter.providerKey = (GUID*)&EBPF_WFP_PROVIDER;
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = *filter_parameter->callout_guid;
        filter.filterCondition = (FWPM_FILTER_CONDITION*)conditions;
        filter.numFilterConditions = condition_count;
        if (filter_parameter->sublayer_guid != NULL) {
            filter.subLayerKey = *(filter_parameter->sublayer_guid);
        } else {
            filter.subLayerKey = EBPF_DEFAULT_SUBLAYER;
        }
        filter.weight.type = FWP_EMPTY; // auto-weight.
        REFERENCE_FILTER_CONTEXT(filter_context);
        filter.rawContext = (uint64_t)(uintptr_t)filter_context;

        status = FwpmFilterAdd(_fwp_engine_handle, &filter, NULL, &local_filter_ids[index]);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(
                NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR,
                "FwpmFilterAdd",
                status,
                "Failed to add filter",
                (char*)filter_parameter->name);
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
    }

    status = FwpmTransactionCommit(_fwp_engine_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpmTransactionCommit", status);
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    is_in_transaction = FALSE;

    *filter_ids = local_filter_ids;

Exit:
    if (!NT_SUCCESS(status)) {
        if (local_filter_ids != NULL) {
            ExFreePool(local_filter_ids);
        }
        if (is_in_transaction) {
            FwpmTransactionAbort(_fwp_engine_handle);
        }
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static NTSTATUS
_net_ebpf_ext_register_wfp_callout(_Inout_ net_ebpf_ext_wfp_callout_state_t* callout_state, _Inout_ void* device_object)
/* ++

   This function registers callouts and filters.

-- */
{
    NTSTATUS status = STATUS_SUCCESS;

    NET_EBPF_EXT_LOG_ENTRY();

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
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(
            NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR,
            "FwpsCalloutRegister",
            status,
            "Failed to register callout",
            (char*)callout_state->name);
        goto Exit;
    }
    was_callout_registered = TRUE;

    display_data.name = callout_state->name;
    display_data.description = callout_state->description;

    callout_add_state.calloutKey = *callout_state->callout_guid;
    callout_add_state.displayData = display_data;
    callout_add_state.providerKey = (GUID*)&EBPF_WFP_PROVIDER;
    callout_add_state.applicableLayer = *callout_state->layer_guid;

    status = FwpmCalloutAdd(_fwp_engine_handle, &callout_add_state, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(
            NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR,
            "FwpmCalloutAdd",
            status,
            "Failed to add callout",
            (char*)callout_state->name);
        goto Exit;
    }

Exit:

    if (!NT_SUCCESS(status)) {
        if (was_callout_registered) {
            status = FwpsCalloutUnregisterById(callout_state->assigned_callout_id);
            if (!NT_SUCCESS(status)) {
                NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                    NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpsCalloutUnregisterById", status);
            } else {
                callout_state->assigned_callout_id = 0;
            }
        }
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

NTSTATUS
net_ebpf_ext_initialize_ndis_handles(_In_ const DRIVER_OBJECT* driver_object)
{
    NTSTATUS status = STATUS_SUCCESS;
    NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_parameters = {0};

    NET_EBPF_EXT_LOG_ENTRY();

    _net_ebpf_ext_ndis_handle =
        NdisAllocateGenericObject((DRIVER_OBJECT*)driver_object, NET_EBPF_EXTENSION_POOL_TAG, 0);
    if (_net_ebpf_ext_ndis_handle == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "NdisAllocateGenericObject", status);
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
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_uninitialize_ndis_handles()
{
    if (_net_ebpf_ext_nbl_pool_handle != NULL) {
        NdisFreeNetBufferListPool(_net_ebpf_ext_nbl_pool_handle);
    }

    if (_net_ebpf_ext_ndis_handle != NULL) {
        NdisFreeGenericObject((NDIS_GENERIC_OBJECT*)_net_ebpf_ext_ndis_handle);
    }
}

NTSTATUS
net_ebpf_extension_initialize_wfp_components(_Inout_ void* device_object)
/* ++

   This function initializes various WFP related components.

-- */
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_PROVIDER ebpf_wfp_provider = {0};
    FWPM_SUBLAYER ebpf_hook_sub_layer;

    UNREFERENCED_PARAMETER(device_object);

    BOOLEAN is_engined_opened = FALSE;
    BOOLEAN is_in_transaction = FALSE;

    FWPM_SESSION session = {0};

    size_t index;

    NET_EBPF_EXT_LOG_ENTRY();

    if (_fwp_engine_handle != NULL) {
        // already registered
        goto Exit;
    }

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &_fwp_engine_handle);
    NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS("FwpmEngineOpen", status);
    is_engined_opened = TRUE;

    status = FwpmTransactionBegin(_fwp_engine_handle, 0);
    NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS("FwpmTransactionBegin", status);
    is_in_transaction = TRUE;

    // Create the WFP provider.
    ebpf_wfp_provider.displayData.name = L"Microsoft Corporation";
    ebpf_wfp_provider.displayData.description = L"Windows Networking eBPF Extension";
    ebpf_wfp_provider.providerKey = EBPF_WFP_PROVIDER;
    status = FwpmProviderAdd(_fwp_engine_handle, &ebpf_wfp_provider, NULL);
    NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS("FwpmProviderAdd", status);

    // Add all the sub layers.
    for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_sublayers); index++) {
        RtlZeroMemory(&ebpf_hook_sub_layer, sizeof(FWPM_SUBLAYER));

        ebpf_hook_sub_layer.subLayerKey = *(_net_ebpf_ext_sublayers[index].sublayer_guid);
        ebpf_hook_sub_layer.displayData.name = (wchar_t*)_net_ebpf_ext_sublayers[index].name;
        ebpf_hook_sub_layer.displayData.description = (wchar_t*)_net_ebpf_ext_sublayers[index].description;
        ebpf_hook_sub_layer.providerKey = (GUID*)&EBPF_WFP_PROVIDER;
        ebpf_hook_sub_layer.flags = _net_ebpf_ext_sublayers[index].flags;
        ebpf_hook_sub_layer.weight = _net_ebpf_ext_sublayers[index].weight;

        status = FwpmSubLayerAdd(_fwp_engine_handle, &ebpf_hook_sub_layer, NULL);
        NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS("FwpmSubLayerAdd", status);
    }

    for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_states); index++) {
        status = _net_ebpf_ext_register_wfp_callout(&_net_ebpf_ext_wfp_callout_states[index], device_object);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_MESSAGE_STRING(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR,
                "_net_ebpf_ext_register_wfp_callout() failed to register callout",
                (char*)_net_ebpf_ext_wfp_callout_states[index].name);
            goto Exit;
        }
    }

    status = FwpmTransactionCommit(_fwp_engine_handle);
    NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS("FwpmTransactionCommit", status);
    is_in_transaction = FALSE;

    // Create L2 injection handle.
    status = FwpsInjectionHandleCreate(AF_LINK, FWPS_INJECTION_TYPE_L2, &_net_ebpf_ext_l2_injection_handle);
    NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS("FwpsInjectionHandleCreate", status);

Exit:

    if (!NT_SUCCESS(status)) {
        if (is_in_transaction) {
            status = FwpmTransactionAbort(_fwp_engine_handle);
            if (!NT_SUCCESS(status)) {
                NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                    NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpmTransactionAbort", status);
            }
        }
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_extension_uninitialize_wfp_components(void)
{
    size_t index;
    if (_fwp_engine_handle != NULL) {
        FwpmEngineClose(_fwp_engine_handle);
        _fwp_engine_handle = NULL;

        for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_states); index++) {
            FwpsCalloutUnregisterById(_net_ebpf_ext_wfp_callout_states[index].assigned_callout_id);
        }
    }

    FwpsInjectionHandleDestroy(_net_ebpf_ext_l2_injection_handle);
}

NTSTATUS
net_ebpf_ext_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ FWPS_FILTER* filter)
{
    NET_EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(filter_key);
    if (callout_notification_type == FWPS_CALLOUT_NOTIFY_DELETE_FILTER) {
        net_ebpf_extension_wfp_filter_context_t* filter_context =
            (net_ebpf_extension_wfp_filter_context_t*)(uintptr_t)filter->context;
        DEREFERENCE_FILTER_CONTEXT((filter_context));
    }

    NET_EBPF_EXT_LOG_FUNCTION_SUCCESS();
    return STATUS_SUCCESS;
}

static void
_net_ebpf_ext_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context)
/* ++

   This is the flowDeleteFn function of the L2 callout.

-- */
{
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);
    UNREFERENCED_PARAMETER(flow_context);
    return;
}

NTSTATUS
net_ebpf_ext_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    NET_EBPF_EXT_LOG_ENTRY();

    status = net_ebpf_ext_xdp_register_providers();
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    _net_ebpf_xdp_providers_registered = true;

    status = net_ebpf_ext_bind_register_providers();
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    _net_ebpf_bind_providers_registered = true;

    status = net_ebpf_ext_sock_addr_register_providers();
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    _net_ebpf_sock_addr_providers_registered = true;

    status = net_ebpf_ext_sock_ops_register_providers();
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    _net_ebpf_sock_ops_providers_registered = true;

Exit:
    if (!NT_SUCCESS(status)) {
        net_ebpf_ext_unregister_providers();
    }
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_unregister_providers()
{
    if (_net_ebpf_xdp_providers_registered) {
        net_ebpf_ext_xdp_unregister_providers();
        _net_ebpf_xdp_providers_registered = false;
    }
    if (_net_ebpf_bind_providers_registered) {
        net_ebpf_ext_bind_unregister_providers();
        _net_ebpf_bind_providers_registered = false;
    }
    if (_net_ebpf_sock_addr_providers_registered) {
        net_ebpf_ext_sock_addr_unregister_providers();
        _net_ebpf_sock_addr_providers_registered = false;
    }
    if (_net_ebpf_sock_ops_providers_registered) {
        net_ebpf_ext_sock_ops_unregister_providers();
        _net_ebpf_sock_ops_providers_registered = false;
    }
}
