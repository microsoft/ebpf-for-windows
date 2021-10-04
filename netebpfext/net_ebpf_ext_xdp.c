// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file This file implements the XDP program type hook and helper functions on eBPF for Windows.
 *
 */

#define INITGUID

// ebpf_xdp_program_data.h has generated
// headers. encode_program_info generates them from the structs
// in ebpf_nethooks.h. This workaround exists due to the inability
// to call RPC serialization services from kernel mode. Once we switch
// to a different serializer, we can get rid of this workaround.
#include "ebpf_xdp_program_data.h"

#include "net_ebpf_ext.h"
#include "net_ebpf_ext_helpers.h"

static ebpf_ext_attach_hook_provider_registration_t* _ebpf_xdp_hook_provider_registration = NULL;
static ebpf_extension_provider_t* _ebpf_xdp_program_info_provider = NULL;

static int
_net_ebpf_xdp_adjust_head(_Inout_ xdp_md_t* ctx, int delta);

static const void* _ebpf_xdp_helper_functions[] = {(void*)&_net_ebpf_xdp_adjust_head, (void*)&_net_ebpf_ext_csum_diff};

static ebpf_helper_function_addresses_t _ebpf_xdp_helper_function_address_table = {
    EBPF_COUNT_OF(_ebpf_xdp_helper_functions), (uint64_t*)_ebpf_xdp_helper_functions};

static ebpf_program_data_t _ebpf_xdp_program_data = {&_ebpf_xdp_program_info, &_ebpf_xdp_helper_function_address_table};

static ebpf_extension_data_t _ebpf_xdp_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_xdp_program_data), &_ebpf_xdp_program_data};

// 85e0d8ef-579e-4931-b072-8ee226bb2e9d
DEFINE_GUID(EBPF_ATTACH_TYPE_XDP, 0x85e0d8ef, 0x579e, 0x4931, 0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d);

// f1832a85-85d5-45b0-98a0-7069d63013b0
DEFINE_GUID(EBPF_PROGRAM_TYPE_XDP, 0xf1832a85, 0x85d5, 0x45b0, 0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0);

typedef struct _net_ebpf_xdp_md
{
    xdp_md_t;
    NET_BUFFER_LIST* original_nbl;
    NET_BUFFER_LIST* cloned_nbl;
} net_ebpf_xdp_md_t;

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

    // Copy the contents of the old NBL into the packet_buffer at the offset after any unused header.
    RtlCopyMemory(packet_buffer + unused_header_length, old_data, old_net_buffer->DataLength);

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
    FWP_ACTION_TYPE action = FWP_ACTION_PERMIT;

    UNREFERENCED_PARAMETER(incoming_metadata_values);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flow_context);
    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layer_data;
    NET_BUFFER* net_buffer = NULL;
    uint8_t* packet_buffer;
    uint32_t result = 0;
    net_ebpf_xdp_md_t net_xdp_ctx = {0};
    NTSTATUS status = STATUS_SUCCESS;

    if (!ebpf_ext_attach_enter_rundown(_ebpf_xdp_hook_provider_registration))
        goto Done;

    if (nbl == NULL) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Null NBL \n"));
        goto Done;
    }

    net_xdp_ctx.ingress_ifindex =
        incoming_fixed_values->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_INDEX].value.uint32;

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

    if (ebpf_ext_attach_invoke_hook(_ebpf_xdp_hook_provider_registration, (xdp_md_t*)&net_xdp_ctx, &result) ==
        EBPF_SUCCESS) {
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

    ebpf_ext_attach_leave_rundown(_ebpf_xdp_hook_provider_registration);
    return;
}

static void
_net_ebpf_ext_xdp_hook_provider_unregister()
{
    ebpf_ext_attach_unregister_provider(_ebpf_xdp_hook_provider_registration);
}

static NTSTATUS
_net_ebpf_ext_xdp_hook_provider_register()
{
    ebpf_result_t return_value;
    return_value = ebpf_ext_attach_register_provider(
        &EBPF_PROGRAM_TYPE_XDP,
        &EBPF_ATTACH_TYPE_XDP,
        EBPF_EXT_HOOK_EXECUTION_DISPATCH,
        &_ebpf_xdp_hook_provider_registration);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    if (return_value != EBPF_SUCCESS) {
        _net_ebpf_ext_xdp_hook_provider_unregister();
        return STATUS_UNSUCCESSFUL;
    } else
        return STATUS_SUCCESS;
}

static void
_net_ebpf_ext_xdp_program_info_provider_unregister()
{
    ebpf_provider_unload(_ebpf_xdp_program_info_provider);
}

static NTSTATUS
_net_ebpf_ext_xdp_program_info_provider_register()
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

Done:
    if (return_value != EBPF_SUCCESS) {
        _net_ebpf_ext_xdp_program_info_provider_unregister();
        return STATUS_UNSUCCESSFUL;
    } else
        return STATUS_SUCCESS;
}

NTSTATUS
net_ebpf_ext_xdp_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    status = _net_ebpf_ext_xdp_program_info_provider_register();
    if (status != STATUS_SUCCESS)
        goto Exit;

    status = _net_ebpf_ext_xdp_hook_provider_register();
    if (status != STATUS_SUCCESS)
        goto Exit;

Exit:
    return status;
}

void
net_ebpf_ext_xdp_unregister_providers()
{
    _net_ebpf_ext_xdp_hook_provider_unregister();
    _net_ebpf_ext_xdp_program_info_provider_unregister();
}