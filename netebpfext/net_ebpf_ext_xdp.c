// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file This file implements the XDP program type hook and helper functions on eBPF for Windows.
 *
 */

#define INITGUID

#include "net_ebpf_ext_xdp.h"

//
// Utility functions.
//
__forceinline static NTSTATUS
_net_ebpf_extension_xdp_validate_if_index(uint32_t if_index)
{
    NTSTATUS status = STATUS_SUCCESS;
    MIB_IF_ROW2* if_row = NULL;
    if_row =
        (MIB_IF_ROW2*)ExAllocatePoolUninitialized(NonPagedPoolNx, sizeof(MIB_IF_ROW2), NET_EBPF_EXTENSION_POOL_TAG);
    if (if_row == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }
    memset(if_row, 0, sizeof(MIB_IF_ROW2));
    if_row->InterfaceIndex = if_index;
    status = GetIfEntry2(if_row);
Exit:
    if (if_row != NULL)
        ExFreePool(if_row);
    return status;
}

//
// WFP XDP layer filter related types & globals.
//

const net_ebpf_extension_wfp_filter_parameters_t _net_ebpf_extension_xdp_wfp_filter_parameters[] = {
    {&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
     &EBPF_HOOK_INBOUND_L2_CALLOUT,
     L"net eBPF xdp hook",
     L"net eBPF xdp hook WFP filter"},
    {&FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
     &EBPF_HOOK_OUTBOUND_L2_CALLOUT,
     L"net eBPF xdp hook",
     L"net eBPF xdp hook WFP filter"}};

#define NET_EBPF_XDP_FILTER_COUNT EBPF_COUNT_OF(_net_ebpf_extension_xdp_wfp_filter_parameters)

typedef struct _net_ebpf_extension_xdp_wfp_filter_context
{
    const net_ebpf_extension_hook_client_t* client_context;
    uint32_t if_index;
    uint64_t filter_ids[NET_EBPF_XDP_FILTER_COUNT];
} net_ebpf_extension_xdp_wfp_filter_context_t;

//
// XDP Program Information NPI Provider.
//
static int
_net_ebpf_xdp_adjust_head(_Inout_ xdp_md_t* ctx, int delta);

static const void* _ebpf_xdp_helper_functions[] = {(void*)&_net_ebpf_xdp_adjust_head};

static ebpf_helper_function_addresses_t _ebpf_xdp_helper_function_address_table = {
    EBPF_COUNT_OF(_ebpf_xdp_helper_functions), (uint64_t*)_ebpf_xdp_helper_functions};

static ebpf_program_data_t _ebpf_xdp_program_data = {&_ebpf_xdp_program_info, &_ebpf_xdp_helper_function_address_table};

static ebpf_extension_data_t _ebpf_xdp_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_xdp_program_data), &_ebpf_xdp_program_data};

// Net eBPF Extension XDP Program Information NPI Provider Module GUID: f4f7e1e4-5f5a-440f-8a62-2880c6db0e87
const NPI_MODULEID DECLSPEC_SELECTANY _ebpf_xdp_program_info_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, {0xf4f7e1e4, 0x5f5a, 0x440f, {0x8a, 0x62, 0x28, 0x80, 0xc6, 0xdb, 0x0e, 0x87}}};

static net_ebpf_extension_program_info_provider_t* _ebpf_xdp_program_info_provider_context = NULL;

//
// XDP Hook NPI Provider.
//

ebpf_attach_provider_data_t _net_ebpf_xdp_hook_provider_data;

ebpf_extension_data_t _net_ebpf_extension_xdp_hook_provider_data = {
    EBPF_ATTACH_PROVIDER_DATA_VERSION, sizeof(_net_ebpf_xdp_hook_provider_data), &_net_ebpf_xdp_hook_provider_data};

// Net eBPF Extension XDP Hook NPI Provider Module GUID: d8039b3a-bdaf-4c54-8d9e-9f88d692f4b9
const NPI_MODULEID DECLSPEC_SELECTANY _ebpf_xdp_hook_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, {0xd8039b3a, 0xbdaf, 0x4c54, {0x8d, 0x9e, 0x9f, 0x88, 0xd6, 0x92, 0xf4, 0xb9}}};

static net_ebpf_extension_hook_provider_t* _ebpf_xdp_hook_provider_context = NULL;

//
// NMR Registration Helper Routines.
//

static ebpf_result_t
net_ebpf_extension_xdp_on_client_attach(_In_ const net_ebpf_extension_hook_client_t* attaching_client)
{
    ebpf_result_t result = EBPF_SUCCESS;
    const ebpf_extension_data_t* client_data = net_ebpf_extension_hook_client_get_client_data(attaching_client);
    uint32_t if_index;
    uint32_t filter_count;
    FWPM_FILTER_CONDITION condition = {0};
    net_ebpf_extension_xdp_wfp_filter_context_t* filter_context = NULL;

    // XDP hook clients must always provide data.
    if (client_data == NULL) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Validate client data.
    if (client_data->version != EBPF_ATTACH_CLIENT_DATA_VERSION) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (client_data->size > 0) {
        if ((client_data->size < sizeof(uint32_t)) || (client_data->data == NULL)) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
        if_index = *(uint32_t*)client_data->data;
    } else {
        // If the client did not specify any attach parameters, we treat that as a wildcard interface index.
        if_index = 0;
    }

    if (if_index == 0) {
        // Client requested wildcard interface. This will only be allowed if there are no other clients attached.
        if (net_ebpf_extension_hook_get_next_attached_client(_ebpf_xdp_hook_provider_context, NULL) != NULL) {
            result = EBPF_ACCESS_DENIED;
            goto Exit;
        }
    } else {
        if (!NT_SUCCESS(_net_ebpf_extension_xdp_validate_if_index(if_index))) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
        // Ensure there are no other clients with interface index 0 or with the same interface index as the
        // requesting client.
        net_ebpf_extension_hook_client_t* next_client =
            net_ebpf_extension_hook_get_next_attached_client(_ebpf_xdp_hook_provider_context, NULL);
        while (next_client != NULL) {
            const ebpf_extension_data_t* next_client_data = net_ebpf_extension_hook_client_get_client_data(next_client);
            uint32_t next_client_if_index = (next_client_data->data == NULL) ? 0 : *(uint32_t*)next_client_data->data;
            if ((next_client_if_index == 0) || (if_index == next_client_if_index)) {
                result = EBPF_ACCESS_DENIED;
                goto Exit;
            }
            next_client =
                net_ebpf_extension_hook_get_next_attached_client(_ebpf_xdp_hook_provider_context, next_client);
        }
    }

    // Set interface index (if non-zero) as WFP filter condition.
    if (if_index != 0) {
        condition.fieldKey = FWPM_CONDITION_INTERFACE_INDEX;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = if_index;
    }

    // Allocate buffer for WFP filter context.
    filter_context = (net_ebpf_extension_xdp_wfp_filter_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_xdp_wfp_filter_context_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (filter_context == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(filter_context, 0, sizeof(net_ebpf_extension_xdp_wfp_filter_context_t));
    filter_context->client_context = attaching_client;
    filter_context->if_index = if_index;

    // Add WFP filters at appropriate layers and set the hook NPI client as the filter's raw context.
    filter_count = NET_EBPF_XDP_FILTER_COUNT;
    result = net_ebpf_extension_add_wfp_filters(
        filter_count,
        _net_ebpf_extension_xdp_wfp_filter_parameters,
        (if_index == 0) ? 0 : 1,
        (if_index == 0) ? NULL : &condition,
        filter_context,
        filter_context->filter_ids);
    if (result != EBPF_SUCCESS)
        goto Exit;

    // Set the filter context as the client context's provider data.
    net_ebpf_extension_hook_client_set_provider_data(
        (net_ebpf_extension_hook_client_t*)attaching_client, filter_context);

Exit:
    if (result != EBPF_SUCCESS) {
        if (filter_context != NULL)
            ExFreePool(filter_context);
    }

    return result;
}

static void
_net_ebpf_extension_xdp_on_client_detach(_In_ const net_ebpf_extension_hook_client_t* detaching_client)
{
    net_ebpf_extension_xdp_wfp_filter_context_t* filter_context =
        (net_ebpf_extension_xdp_wfp_filter_context_t*)net_ebpf_extension_hook_client_get_provider_data(
            detaching_client);
    ASSERT(filter_context != NULL);
    net_ebpf_extension_delete_wfp_filters(NET_EBPF_XDP_FILTER_COUNT, filter_context->filter_ids);
    ExFreePool(filter_context);
}

NTSTATUS
net_ebpf_ext_xdp_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;
    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &EBPF_PROGRAM_TYPE_XDP, &_ebpf_xdp_program_info_provider_moduleid, &_ebpf_xdp_program_info_provider_data};
    const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &EBPF_ATTACH_TYPE_XDP,
        &_ebpf_xdp_hook_provider_moduleid,
        &_net_ebpf_extension_xdp_hook_provider_data,
        EXECUTION_DISPATCH};

    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_xdp_program_info_provider_context);
    if (status != STATUS_SUCCESS)
        goto Exit;

    _net_ebpf_xdp_hook_provider_data.supported_program_type = EBPF_PROGRAM_TYPE_XDP;

    status = net_ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        net_ebpf_extension_xdp_on_client_attach,
        _net_ebpf_extension_xdp_on_client_detach,
        &_ebpf_xdp_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    return status;
}

void
net_ebpf_ext_xdp_unregister_providers()
{
    net_ebpf_extension_hook_provider_unregister(_ebpf_xdp_hook_provider_context);
    net_ebpf_extension_program_info_provider_unregister(_ebpf_xdp_program_info_provider_context);
}

/**
 *  @brief This is the internal data structure for XDP context.
 */
typedef struct _net_ebpf_xdp_md
{
    xdp_md_t;
    NET_BUFFER_LIST* original_nbl;
    NET_BUFFER_LIST* cloned_nbl;
} net_ebpf_xdp_md_t;

//
// NBL Clone Functions.
//

static void
_net_ebpf_ext_free_nbl(_Inout_ NET_BUFFER_LIST* nbl);

static NTSTATUS
_net_ebpf_ext_allocate_cloned_nbl(_Inout_ net_ebpf_xdp_md_t* net_xdp_ctx, uint32_t unused_header_length)
{
    NTSTATUS status = STATUS_SUCCESS;
    uint8_t* old_data;
    NET_BUFFER_LIST* old_nbl = NULL;
    NET_BUFFER* old_net_buffer = NULL;
    NET_BUFFER_LIST* new_nbl = NULL;
    uint32_t cloned_net_buffer_length = 0;
    uint8_t* packet_buffer = NULL;
    MDL* mdl_chain = NULL;

    // Either original or cloned NBL must be present.
    if ((net_xdp_ctx->original_nbl == NULL) && (net_xdp_ctx->cloned_nbl == NULL)) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    old_data = net_xdp_ctx->data;

    old_nbl = (net_xdp_ctx->cloned_nbl != NULL) ? net_xdp_ctx->cloned_nbl : net_xdp_ctx->original_nbl;
    ASSERT(old_nbl != NULL);
    old_net_buffer = NET_BUFFER_LIST_FIRST_NB(old_nbl);

    // Allocate buffer for the cloned NBL, accounting for any unused header.
    status = RtlULongAdd(old_net_buffer->DataLength, unused_header_length, (ULONG*)&cloned_net_buffer_length);
    if (!NT_SUCCESS(status))
        goto Exit;

    packet_buffer =
        (void*)ExAllocatePoolUninitialized(NonPagedPoolNx, cloned_net_buffer_length, NET_EBPF_EXTENSION_POOL_TAG);
    if (packet_buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(packet_buffer, cloned_net_buffer_length);

    if (old_data != NULL) {
        // Copy the contents of the old NBL into the packet_buffer at the offset after any unused header.
        RtlCopyMemory(packet_buffer + unused_header_length, old_data, old_net_buffer->DataLength);
    } else {
        // This is the case when we received a NB with more than one MDL. Get contiguous data buffer
        // from NB and copy to packet_buffer at the offset after any unused header.
        uint8_t* buffer =
            NdisGetDataBuffer(old_net_buffer, old_net_buffer->DataLength, packet_buffer + unused_header_length, 1, 0);
        if (buffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
    }

    // Adjust the XDP context data pointers.
    net_xdp_ctx->data = packet_buffer;
    net_xdp_ctx->data_end = packet_buffer + cloned_net_buffer_length;

    // Create a MDL with the packet buffer.
    mdl_chain = IoAllocateMdl(packet_buffer, cloned_net_buffer_length, FALSE, FALSE, NULL);
    if (mdl_chain == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    MmBuildMdlForNonPagedPool(mdl_chain);

    // Now allocate the cloned NBL using this MDL chain.
    status = FwpsAllocateNetBufferAndNetBufferList(
        _net_ebpf_ext_nbl_pool_handle, 0, 0, mdl_chain, 0, cloned_net_buffer_length, &new_nbl);
    if (!NT_SUCCESS(status))
        goto Exit;
    mdl_chain = NULL;
    packet_buffer = NULL;

    // Set the new NBL as the cloned NBL in XDP context, after disposing any previous clones.
    if (net_xdp_ctx->cloned_nbl != NULL)
        _net_ebpf_ext_free_nbl(net_xdp_ctx->cloned_nbl);
    net_xdp_ctx->cloned_nbl = new_nbl;

Exit:
    if (mdl_chain != NULL)
        IoFreeMdl(mdl_chain);
    if (packet_buffer != NULL)
        ExFreePool(packet_buffer);
    return status;
}

static void
_net_ebpf_ext_free_nbl(_Inout_ NET_BUFFER_LIST* nbl)
{
    NET_BUFFER* net_buffer = NET_BUFFER_LIST_FIRST_NB(nbl);
    MDL* mdl_chain = NET_BUFFER_FIRST_MDL(net_buffer);
    uint8_t* buffer = MmGetSystemAddressForMdlSafe(mdl_chain, NormalPagePriority);
    if (buffer != NULL)
        ExFreePool(buffer);
    IoFreeMdl(mdl_chain);
    FwpsFreeNetBufferList0(nbl);
}

//
// XDP Helper Functions.
//

static int
_net_ebpf_xdp_adjust_head(_Inout_ xdp_md_t* ctx, int delta)
{
    int return_value = 0;
    NDIS_STATUS ndis_status = NDIS_STATUS_SUCCESS;
    net_ebpf_xdp_md_t* net_xdp_ctx = (net_ebpf_xdp_md_t*)ctx;
    NET_BUFFER_LIST* nbl = NULL;
    NET_BUFFER* net_buffer = NULL;
    uint8_t* packet_buffer = NULL;

    // Either original or cloned NBL must be present.
    if ((net_xdp_ctx->original_nbl == NULL) && (net_xdp_ctx->cloned_nbl == NULL)) {
        return_value = -1;
        goto Exit;
    }

    nbl = (net_xdp_ctx->cloned_nbl != NULL) ? net_xdp_ctx->cloned_nbl : net_xdp_ctx->original_nbl;
    ASSERT(nbl != NULL);
    net_buffer = NET_BUFFER_LIST_FIRST_NB(nbl);

    if (delta == 0)
        // Nothing to do.
        goto Exit;
    if (delta < 0) {
        uint32_t absolute_delta = -delta;
        ndis_status = NdisRetreatNetBufferDataStart(net_buffer, absolute_delta, 0, NULL);
        if (ndis_status != NDIS_STATUS_SUCCESS) {
            return_value = -1;
            goto Exit;
        }
        packet_buffer = NdisGetDataBuffer(net_buffer, net_buffer->DataLength, NULL, 1, 0);
        if (packet_buffer != NULL)
            net_xdp_ctx->data = packet_buffer;
        else {
            // Data in net_buffer not contiguous.
            // Restore net_buffer.
            NdisAdvanceNetBufferDataStart(net_buffer, absolute_delta, TRUE, NULL);
            // Allocate a cloned NBL with contiguous data.
            _net_ebpf_ext_allocate_cloned_nbl(net_xdp_ctx, absolute_delta);
        }
    } else {
        // delta > 0.
        NdisAdvanceNetBufferDataStart(net_buffer, delta, FALSE, NULL);
        packet_buffer = NdisGetDataBuffer(net_buffer, net_buffer->DataLength, NULL, 1, 0);
        ASSERT(packet_buffer != NULL);
        net_xdp_ctx->data = packet_buffer;
    }

Exit:
    return return_value;
}

//
// Packet Injection Routines.
//

static void
_net_ebpf_ext_l2_receive_inject_complete(_In_ const void* context, _Inout_ NET_BUFFER_LIST* nbl, BOOLEAN dispatch_level)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(dispatch_level);
    // Free clone allocated using _net_ebpf_ext_allocate_cloned_nbl.
    _net_ebpf_ext_free_nbl(nbl);
}

static FWP_ACTION_TYPE
_net_ebpf_ext_receive_inject_cloned_nbl(
    _In_ const NET_BUFFER_LIST* cloned_nbl, _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values)
{
    uint32_t interface_index =
        incoming_fixed_values->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_INDEX].value.uint32;
    uint32_t ndis_port =
        incoming_fixed_values->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_NDIS_PORT].value.uint32;

    return FwpsInjectMacReceiveAsync(
        _net_ebpf_ext_l2_injection_handle,
        NULL,
        0,
        FWPS_LAYER_INBOUND_MAC_FRAME_NATIVE,
        interface_index,
        ndis_port,
        (NET_BUFFER_LIST*)cloned_nbl,
        _net_ebpf_ext_l2_receive_inject_complete,
        NULL);
}

static void
_net_ebpf_ext_l2_inject_send_complete(_In_ const void* context, _Inout_ NET_BUFFER_LIST* nbl, BOOLEAN dispatch_level)
{
    if ((BOOLEAN)(uintptr_t)context == FALSE)
        // Free clone allocated using _net_ebpf_ext_allocate_cloned_nbl.
        _net_ebpf_ext_free_nbl(nbl);
    else
        // Free clone allocated using FwpsAllocateCloneNetBufferList.
        FwpsFreeCloneNetBufferList(nbl, dispatch_level);
}

static void
_net_ebpf_ext_handle_xdp_tx(
    _Inout_ net_ebpf_xdp_md_t* net_xdp_ctx, _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values)
{
    NET_BUFFER_LIST* nbl = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOL cloned_packet = FALSE;

    uint32_t interface_index =
        incoming_fixed_values->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_INDEX].value.uint32;
    uint32_t ndis_port =
        incoming_fixed_values->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_NDIS_PORT].value.uint32;

    // Either original or cloned NBL must be present.
    ASSERT((net_xdp_ctx->original_nbl != NULL) || (net_xdp_ctx->cloned_nbl != NULL));

    if (net_xdp_ctx->cloned_nbl != NULL)
        // No need to clone an already cloned NBL.
        nbl = net_xdp_ctx->cloned_nbl;
    else {
        status = FwpsAllocateCloneNetBufferList(net_xdp_ctx->original_nbl, NULL, NULL, 0, &nbl);
        if (status != STATUS_SUCCESS)
            goto Exit;
        cloned_packet = TRUE;
    }

    status = FwpsInjectMacSendAsync(
        _net_ebpf_ext_l2_injection_handle,
        NULL,
        0,
        FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
        interface_index,
        ndis_port,
        nbl,
        _net_ebpf_ext_l2_inject_send_complete,
        (void*)(uintptr_t)cloned_packet);

    if (status != STATUS_SUCCESS)
        goto Exit;

Exit:
    return;
}

//
// WFP Classify callback.
//

void
net_ebpf_ext_layer_2_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWP_ACTION_TYPE action = FWP_ACTION_PERMIT;
    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layer_data;
    NET_BUFFER* net_buffer = NULL;
    uint8_t* packet_buffer;
    uint32_t result = 0;
    net_ebpf_xdp_md_t net_xdp_ctx = {0};
    net_ebpf_extension_xdp_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_hook_client_t* attached_client = NULL;
    uint32_t client_if_index;

    UNREFERENCED_PARAMETER(incoming_metadata_values);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    //
    // WFP MAC layers are implemented using NDIS light-weight filters (LWF).
    // See https://docs.microsoft.com/en-us/windows-hardware/drivers/network/using-layer-2-filtering for details.
    // FwpsInjectMacSendAsync API is used for injecting packets in the outbound direction to implement XDP_TX.
    // For packet injection to work WFP LWF must register packet send-completion handlers with NDIS.
    // This handler is added only if WFP filters/callouts are added in the FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE layer.
    // That is why a filter and a callout is added in this layer even though the callout at the outbound layer
    // need not process any outbound packets.
    //
    if (incoming_fixed_values->layerId == FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE)
        goto Done;

    filter_context = (net_ebpf_extension_xdp_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->client_context;
    ASSERT(attached_client != NULL);
    if (attached_client == NULL)
        goto Done;

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client, EXECUTION_DISPATCH))
        goto Done;

    if (nbl == NULL) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Null NBL \n"));
        goto Done;
    }

    net_xdp_ctx.ingress_ifindex =
        incoming_fixed_values->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_INDEX].value.uint32;

    client_if_index = filter_context->if_index;
    ASSERT((client_if_index == 0) || (client_if_index == net_xdp_ctx.ingress_ifindex));
    if (client_if_index != 0 && client_if_index != net_xdp_ctx.ingress_ifindex) {
        // The client is not interested in this ingress ifindex.
        goto Done;
    }

    net_xdp_ctx.original_nbl = nbl;

    net_buffer = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (net_buffer == NULL) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "net_buffer not present\n"));
        // nothing to do
        goto Done;
    }

    packet_buffer = NdisGetDataBuffer(net_buffer, net_buffer->DataLength, NULL, sizeof(uint16_t), 0);
    if (!packet_buffer) {
        // Data in net_buffer not contiguous.
        // Allocate a cloned NBL with contiguous data.
        status = _net_ebpf_ext_allocate_cloned_nbl(&net_xdp_ctx, 0);
        if (!NT_SUCCESS(status))
            goto Done;
    } else {
        net_xdp_ctx.data = packet_buffer;
        net_xdp_ctx.data_end = packet_buffer + net_buffer->DataLength;
    }

    if (net_ebpf_extension_hook_invoke_program(attached_client, &net_xdp_ctx, &result) == EBPF_SUCCESS) {
        switch (result) {
        case XDP_PASS:
            if (net_xdp_ctx.cloned_nbl != NULL) {
                // Drop the orignal NBL.
                action = FWP_ACTION_BLOCK;

                // Inject the cloned NBL in receive path.
                status = _net_ebpf_ext_receive_inject_cloned_nbl(net_xdp_ctx.cloned_nbl, incoming_fixed_values);
                if (NT_SUCCESS(status))
                    // If cloned packet could be successfully injected, no need to audit for dropping the original.
                    // So absorb the original packet.
                    classify_output->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            }
            // No special processing required in the non-clone case.
            // The inbound original NBL will be allowed to proceed in the ingress path.
            break;
        case XDP_TX:
            _net_ebpf_ext_handle_xdp_tx(&net_xdp_ctx, incoming_fixed_values);
            // Absorb the original NBL.
            action = FWP_ACTION_BLOCK;
            classify_output->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            break;
        case XDP_DROP:
            action = FWP_ACTION_BLOCK;
            // Do not audit XDP drops.
            classify_output->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            // Free cloned NBL, if any.
            if (net_xdp_ctx.cloned_nbl != NULL)
                _net_ebpf_ext_free_nbl(net_xdp_ctx.cloned_nbl);
            break;
        }
    }
Done:
    classify_output->actionType = action;

    if (attached_client)
        net_ebpf_extension_hook_client_leave_rundown(attached_client, EXECUTION_DISPATCH);

    return;
}