// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/*++

Abstract:

   This file implements the classifyFn, notifiFn, and flowDeleteFn callouts
   functions for:
   Layer 2 network receive
   Resource Acquire
   Resource Release
   Bind redirect

Environment:

    Kernel mode

--*/
#define INITGUID

#include "net_ebpf_ext.h"

#pragma warning(push)
#pragma warning(disable : 4201) // unnamed struct/union
#include <fwpsk.h>
#pragma warning(pop)

#include <fwpmk.h>
#include <guiddef.h>
#include <netiodef.h>
#include <ntddk.h>

#include "ebpf_ext_attach_provider.h"
// ebpf_bind_program_data.h and ebpf_xdp_program_data.h are generated
// headers. encode_program_info generates them from the structs
// in ebpf_nethooks.h. This workaround exists due to the inability
// to call RPC serialization services from kernel mode. Once we switch
// to a different serializer, we can get rid of this workaround.
#include "ebpf_bind_program_data.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_windows.h"
#include "ebpf_xdp_program_data.h"

static ebpf_ext_attach_hook_provider_registration_t* _ebpf_xdp_hook_provider_registration = NULL;
static ebpf_ext_attach_hook_provider_registration_t* _ebpf_bind_hook_provider_registration = NULL;
static ebpf_extension_provider_t* _ebpf_xdp_program_info_provider = NULL;
static ebpf_extension_provider_t* _ebpf_bind_program_info_provider = NULL;

#define RTL_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))

#define NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

static ebpf_context_descriptor_t _ebpf_xdp_context_descriptor = {
    sizeof(xdp_md_t),
    EBPF_OFFSET_OF(xdp_md_t, data),
    EBPF_OFFSET_OF(xdp_md_t, data_end),
    EBPF_OFFSET_OF(xdp_md_t, data_meta)};
static ebpf_program_info_t _ebpf_xdp_program_info = {{"xdp", &_ebpf_xdp_context_descriptor, {0}}, 0, NULL};

static ebpf_program_data_t _ebpf_xdp_program_data = {&_ebpf_xdp_program_info, NULL};

static ebpf_extension_data_t _ebpf_xdp_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_xdp_program_data), &_ebpf_xdp_program_data};

static ebpf_context_descriptor_t _ebpf_bind_context_descriptor = {
    sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};
static ebpf_program_info_t _ebpf_bind_program_info = {{"bind", &_ebpf_bind_context_descriptor, {0}}, 0, NULL};

static ebpf_program_data_t _ebpf_bind_program_data = {&_ebpf_bind_program_info, NULL};

static ebpf_extension_data_t _ebpf_bind_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_bind_program_data), &_ebpf_bind_program_data};
// Callout and sublayer GUIDs

// 7c7b3fb9-3331-436a-98e1-b901df457fff
DEFINE_GUID(EBPF_HOOK_SUBLAYER, 0x7c7b3fb9, 0x3331, 0x436a, 0x98, 0xe1, 0xb9, 0x01, 0xdf, 0x45, 0x7f, 0xff);

// 5a5614e5-6b64-4738-8367-33c6ca07bf8f
DEFINE_GUID(EBPF_HOOK_L2_CALLOUT, 0x5a5614e5, 0x6b64, 0x4738, 0x83, 0x67, 0x33, 0xc6, 0xca, 0x07, 0xbf, 0x8f);

// c69f4de0-3d80-457d-9aea-75faef42ec12
DEFINE_GUID(
    EBPF_HOOK_ALE_BIND_REDIRECT_CALLOUT, 0xc69f4de0, 0x3d80, 0x457d, 0x9a, 0xea, 0x75, 0xfa, 0xef, 0x42, 0xec, 0x12);

// 732acf94-7319-4fed-97d0-41d3a18f3fa1
DEFINE_GUID(
    EBPF_HOOK_ALE_RESOURCE_ALLOCATION_CALLOUT,
    0x732acf94,
    0x7319,
    0x4fed,
    0x97,
    0xd0,
    0x41,
    0xd3,
    0xa1,
    0x8f,
    0x3f,
    0xa1);

// d5792949-2d91-4023-9993-3f3dd9d54b2b
DEFINE_GUID(
    EBPF_HOOK_ALE_RESOURCE_RELEASE_CALLOUT, 0xd5792949, 0x2d91, 0x4023, 0x99, 0x93, 0x3f, 0x3d, 0xd9, 0xd5, 0x4b, 0x2b);

// 85e0d8ef-579e-4931-b072-8ee226bb2e9d
DEFINE_GUID(EBPF_ATTACH_TYPE_XDP, 0x85e0d8ef, 0x579e, 0x4931, 0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d);

// b9707e04-8127-4c72-833e-05b1fb439496
DEFINE_GUID(EBPF_ATTACH_TYPE_BIND, 0xb9707e04, 0x8127, 0x4c72, 0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96);

DEFINE_GUID(EBPF_PROGRAM_TYPE_XDP, 0xf1832a85, 0x85d5, 0x45b0, 0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0);

DEFINE_GUID(EBPF_PROGRAM_TYPE_BIND, 0x608c517c, 0x6c52, 0x4a26, 0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf);

static void
_net_ebpf_ext_layer_2_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output);

static void
_net_ebpf_ext_resource_allocation_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output);

static void
_net_ebpf_ext_resource_release_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output);

static void
_net_ebpf_ext_no_op_flow_delete(uint16_t layer_id, uint32_t fwpm_callout_id, uint64_t flow_context);

static NTSTATUS
_net_ebpf_ext_no_op_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ const FWPS_FILTER* filter);

typedef struct _net_ebpf_ext_wfp_callout_state
{
    const GUID* callout_guid;
    const GUID* layer_guid;
    FWPS_CALLOUT_CLASSIFY_FN3 classify_fn;
    FWPS_CALLOUT_NOTIFY_FN3 notify_fn;
    FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 delete_fn;
    wchar_t* name;
    wchar_t* description;
    FWP_ACTION_TYPE filter_action_type;
    uint32_t assigned_callout_id;
} net_ebpf_ext_wfp_callout_state_t;

static net_ebpf_ext_wfp_callout_state_t _net_ebpf_ext_wfp_callout_state[] = {
    {
        &EBPF_HOOK_L2_CALLOUT,
        &FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
        _net_ebpf_ext_layer_2_classify,
        _net_ebpf_ext_no_op_notify,
        _net_ebpf_ext_no_op_flow_delete,
        L"L2 XDP Callout",
        L"L2 callout driver for eBPF at XDP-like layer",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_ALE_RESOURCE_ALLOCATION_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        _net_ebpf_ext_resource_allocation_classify,
        _net_ebpf_ext_no_op_notify,
        _net_ebpf_ext_no_op_flow_delete,
        L"Resource Allocation eBPF Callout",
        L"Resource Allocation callout driver for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    {
        &EBPF_HOOK_ALE_RESOURCE_RELEASE_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_RELEASE_V4,
        _net_ebpf_ext_resource_release_classify,
        _net_ebpf_ext_no_op_notify,
        _net_ebpf_ext_no_op_flow_delete,
        L"Resource Release eBPF Callout",
        L"Resource Release callout driver for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
};

// Callout globals
static HANDLE _fwp_engine_handle;

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
    FWPM_FILTER filter = {0};

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

    filter.layerKey = *callout_state->layer_guid;
    filter.displayData.name = callout_state->name;
    filter.displayData.description = callout_state->description;
    filter.action.type = callout_state->filter_action_type;
    filter.action.calloutKey = *callout_state->callout_guid;
    filter.filterCondition = NULL;
    filter.numFilterConditions = 0;
    filter.subLayerKey = EBPF_HOOK_SUBLAYER;
    filter.weight.type = FWP_EMPTY; // auto-weight.

    status = FwpmFilterAdd(_fwp_engine_handle, &filter, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "NetEbpfExt: FwpmFilterAdd for %S failed with error %.2X\n",
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
net_ebpf_ext_register_callouts(_Inout_ void* device_object)
/* ++

   This function registers dynamic callouts and filters that
   FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET layer.

   Callouts and filters will be removed during DriverUnload.

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

    ebpf_hook_sub_layer.subLayerKey = EBPF_HOOK_SUBLAYER;
    ebpf_hook_sub_layer.displayData.name = L"EBPF hook Sub-Layer";
    ebpf_hook_sub_layer.displayData.description = L"Sub-Layer for use by EBPF callouts";
    ebpf_hook_sub_layer.flags = 0;
    ebpf_hook_sub_layer.weight = FWP_EMPTY; // auto-weight.;

    status = FwpmSubLayerAdd(_fwp_engine_handle, &ebpf_hook_sub_layer, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "NetEbpfExt: FwpmSubLayerAdd failed with error %.2X\n", status));
        goto Exit;
    }

    for (index = 0; index < RTL_COUNT_OF(_net_ebpf_ext_wfp_callout_state); index++) {
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

Exit:

    if (!NT_SUCCESS(status)) {
        if (is_in_transaction) {
            FwpmTransactionAbort(_fwp_engine_handle);
            _Analysis_assume_lock_not_held_(_fwp_engine_handle); // Potential leak if "FwpmTransactionAbort" fails
        }
        if (is_engined_opened) {
            FwpmEngineClose(_fwp_engine_handle);
            _fwp_engine_handle = NULL;
        }
    }

    return status;
}

void
net_ebpf_ext_unregister_callouts(void)
{
    size_t index;
    if (_fwp_engine_handle != NULL) {
        FwpmEngineClose(_fwp_engine_handle);
        _fwp_engine_handle = NULL;

        for (index = 0; index < RTL_COUNT_OF(_net_ebpf_ext_wfp_callout_state); index++) {
            FwpsCalloutUnregisterById(_net_ebpf_ext_wfp_callout_state[index].assigned_callout_id);
        }
    }
}

static void
_net_ebpf_ext_layer_2_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
/* ++

   A simple classify function at the WFP L2 MAC layer.

-- */
{
    FWP_ACTION_TYPE action = FWP_ACTION_PERMIT;
    UNREFERENCED_PARAMETER(incoming_fixed_values);
    UNREFERENCED_PARAMETER(incoming_metadata_values);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flow_context);
    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layer_data;
    NET_BUFFER* net_buffer = NULL;
    uint8_t* packet_buffer;
    uint32_t result = 0;

    if (!ebpf_ext_attach_enter_rundown(_ebpf_xdp_hook_provider_registration))
        goto done;

    if (nbl == NULL) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Null nbl \n"));
        goto done;
    }

    net_buffer = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (net_buffer == NULL) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "net_buffer not present\n"));
        // nothing to do
        goto done;
    }

    packet_buffer = NdisGetDataBuffer(net_buffer, net_buffer->DataLength, NULL, sizeof(uint16_t), 0);
    if (!packet_buffer) {
        goto done;
    }

    xdp_md_t ctx = {packet_buffer, packet_buffer + net_buffer->DataLength};

    if (ebpf_ext_attach_invoke_hook(_ebpf_xdp_hook_provider_registration, &ctx, &result) == EBPF_SUCCESS) {
        switch (result) {
        case XDP_PASS:
            action = FWP_ACTION_PERMIT;
            break;
        case XDP_DROP:
            action = FWP_ACTION_BLOCK;
            break;
        }
    }
done:
    classify_output->actionType = action;

    ebpf_ext_attach_leave_rundown(_ebpf_xdp_hook_provider_registration);
    return;
}

static void
_net_ebpf_ext_resource_truncate_appid(bind_md_t* ctx)
{
    wchar_t* last_separator = (wchar_t*)ctx->app_id_start;
    for (wchar_t* position = (wchar_t*)ctx->app_id_start; position < (wchar_t*)ctx->app_id_end; position++) {
        if (*position == '\\') {
            last_separator = position;
        }
    }
    if (*last_separator == '\\') {
        last_separator++;
    }
    ctx->app_id_start = (uint8_t*)last_separator;
}

static void
_net_ebpf_ext_resource_allocation_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
/* ++

   A simple classify function at the WFP Resource Allocation layer.

-- */
{
    SOCKADDR_IN addr = {AF_INET};
    uint32_t result;
    bind_md_t ctx;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flow_context);

    if (!ebpf_ext_attach_enter_rundown(_ebpf_bind_hook_provider_registration)) {
        classify_output->actionType = FWP_ACTION_PERMIT;
        goto Exit;
    }

    addr.sin_port =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT].value.uint16;
    addr.sin_addr.S_un.S_addr =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS].value.uint32;

    ctx.process_id = incoming_metadata_values->processId;
    memcpy(&ctx.socket_address, &addr, sizeof(addr));
    ctx.operation = BIND_OPERATION_BIND;
    ctx.protocol = incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL].value.uint8;

    ctx.app_id_start =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_APP_ID].value.byteBlob->data;
    ctx.app_id_end =
        ctx.app_id_start +
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_APP_ID].value.byteBlob->size;

    _net_ebpf_ext_resource_truncate_appid(&ctx);
    if (ebpf_ext_attach_invoke_hook(_ebpf_bind_hook_provider_registration, &ctx, &result) == EBPF_SUCCESS) {
        switch (result) {
        case BIND_PERMIT:
        case BIND_REDIRECT:
            classify_output->actionType = FWP_ACTION_PERMIT;
            break;
        case BIND_DENY:
            classify_output->actionType = FWP_ACTION_BLOCK;
        }
    }

Exit:
    ebpf_ext_attach_leave_rundown(_ebpf_bind_hook_provider_registration);
    return;
}

static void
_net_ebpf_ext_resource_release_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
/* ++

   A simple classify function at the WFP Resource Release layer.

-- */
{
    SOCKADDR_IN addr = {AF_INET};
    uint32_t result;
    bind_md_t ctx;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flow_context);

    if (!ebpf_ext_attach_enter_rundown(_ebpf_bind_hook_provider_registration)) {
        classify_output->actionType = FWP_ACTION_PERMIT;
        goto Exit;
    }

    addr.sin_port = incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_PORT].value.uint16;
    addr.sin_addr.S_un.S_addr =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_ADDRESS].value.uint32;

    ctx.process_id = incoming_metadata_values->processId;
    memcpy(&ctx.socket_address, &addr, sizeof(addr));
    ctx.operation = BIND_OPERATION_UNBIND;
    ctx.protocol = incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_PROTOCOL].value.uint8;

    ctx.app_id_start =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_APP_ID].value.byteBlob->data;
    ctx.app_id_end =
        ctx.app_id_start +
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_APP_ID].value.byteBlob->size;

    _net_ebpf_ext_resource_truncate_appid(&ctx);

    ebpf_ext_attach_invoke_hook(_ebpf_bind_hook_provider_registration, &ctx, &result);

    classify_output->actionType = FWP_ACTION_PERMIT;

Exit:
    ebpf_ext_attach_leave_rundown(_ebpf_bind_hook_provider_registration);
    return;
}

static NTSTATUS
_net_ebpf_ext_no_op_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ const FWPS_FILTER* filter)
{
    UNREFERENCED_PARAMETER(callout_notification_type);
    UNREFERENCED_PARAMETER(filter_key);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

static void
_net_ebpf_ext_no_op_flow_delete(uint16_t layer_id, uint32_t fwpm_callout_id, uint64_t flow_context)
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
    ebpf_result_t return_value;
    return_value = ebpf_ext_attach_register_provider(
        &EBPF_PROGRAM_TYPE_XDP,
        &EBPF_ATTACH_TYPE_XDP,
        EBPF_EXT_HOOK_EXECUTION_DISPATCH,
        &_ebpf_xdp_hook_provider_registration);
    if (return_value != EBPF_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    return_value = ebpf_ext_attach_register_provider(
        &EBPF_PROGRAM_TYPE_BIND,
        &EBPF_ATTACH_TYPE_BIND,
        EBPF_EXT_HOOK_EXECUTION_PASSIVE,
        &_ebpf_bind_hook_provider_registration);

    if (return_value != EBPF_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

void
net_ebpf_ext_unregister_providers()
{
    ebpf_ext_attach_unregister_provider(_ebpf_xdp_hook_provider_registration);
    ebpf_ext_attach_unregister_provider(_ebpf_bind_hook_provider_registration);
}

void
net_ebpf_ext_program_info_provider_unregister()
{
    ebpf_provider_unload(_ebpf_xdp_program_info_provider);
    ebpf_provider_unload(_ebpf_bind_program_info_provider);
}

NTSTATUS
net_ebpf_ext_program_info_provider_register()
{
    ebpf_result_t return_value;
    ebpf_extension_data_t* provider_data;
    ebpf_program_data_t* program_data;

    provider_data = &_ebpf_xdp_program_info_provider_data;
    program_data = (ebpf_program_data_t*)provider_data->data;
    program_data->program_info->program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_XDP;

    return_value = ebpf_provider_load(
        &_ebpf_xdp_program_info_provider,
        &EBPF_PROGRAM_TYPE_XDP,
        NULL,
        &_ebpf_xdp_program_info_provider_data,
        NULL,
        NULL,
        NULL,
        NULL);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    provider_data = &_ebpf_bind_program_info_provider_data;
    program_data = (ebpf_program_data_t*)provider_data->data;
    program_data->program_info->program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_BIND;

    return_value = ebpf_provider_load(
        &_ebpf_bind_program_info_provider,
        &EBPF_PROGRAM_TYPE_BIND,
        NULL,
        &_ebpf_bind_program_info_provider_data,
        NULL,
        NULL,
        NULL,
        NULL);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    if (return_value != EBPF_SUCCESS) {
        net_ebpf_ext_program_info_provider_unregister();
        return STATUS_UNSUCCESSFUL;
    } else
        return STATUS_SUCCESS;
}
