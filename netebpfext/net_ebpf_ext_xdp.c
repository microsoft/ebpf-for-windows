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

HANDLE _net_ebpf_ext_l2_injection_handle = NULL;
static ebpf_ext_attach_hook_provider_registration_t* _ebpf_xdp_hook_provider_registration = NULL;
static ebpf_extension_provider_t* _ebpf_xdp_program_info_provider = NULL;

static int
_net_ebpf_xdp_adjust_head(xdp_md_t* ctx, int delta)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(delta);
    return -1;
}

static const void* _ebpf_xdp_helper_functions[] = {(void*)&_net_ebpf_xdp_adjust_head};

static ebpf_helper_function_addresses_t _ebpf_xdp_helper_function_address_table = {
    EBPF_COUNT_OF(_ebpf_xdp_helper_functions), (uint64_t*)_ebpf_xdp_helper_functions};

static ebpf_program_data_t _ebpf_xdp_program_data = {&_ebpf_xdp_program_info, &_ebpf_xdp_helper_function_address_table};

static ebpf_extension_data_t _ebpf_xdp_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_xdp_program_data), &_ebpf_xdp_program_data};

// 85e0d8ef-579e-4931-b072-8ee226bb2e9d
DEFINE_GUID(EBPF_ATTACH_TYPE_XDP, 0x85e0d8ef, 0x579e, 0x4931, 0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d);

// f1832a85-85d5-45b0-98a0-7069d63013b0
DEFINE_GUID(EBPF_PROGRAM_TYPE_XDP, 0xf1832a85, 0x85d5, 0x45b0, 0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0);

static void
_net_ebpf_ext_l2_inject_complete(
    _In_ const void* context, _Inout_ NET_BUFFER_LIST* packet_clone, BOOLEAN dispatch_level)
{
    UNREFERENCED_PARAMETER(context);
    FwpsFreeCloneNetBufferList(packet_clone, dispatch_level);
}

static void
_net_ebpf_ext_handle_xdp_tx(_Inout_ NET_BUFFER_LIST* packet, _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values)
{
    NET_BUFFER_LIST* packet_clone = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    uint32_t interface_index =
        incoming_fixed_values->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_INDEX].value.uint32;
    uint32_t ndis_port =
        incoming_fixed_values->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_NDIS_PORT].value.uint32;

    status = FwpsAllocateCloneNetBufferList(packet, NULL, NULL, 0, &packet_clone);
    if (status != STATUS_SUCCESS)
        goto Exit;

    status = FwpsInjectMacSendAsync(
        _net_ebpf_ext_l2_injection_handle,
        NULL,
        0,
        FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
        interface_index,
        ndis_port,
        packet_clone,
        _net_ebpf_ext_l2_inject_complete,
        NULL);

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

    if (!ebpf_ext_attach_enter_rundown(_ebpf_xdp_hook_provider_registration))
        goto done;

    if (nbl == NULL) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Null NBL \n"));
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
        case XDP_TX:
            _net_ebpf_ext_handle_xdp_tx(nbl, incoming_fixed_values);
            // Fall through.
        case XDP_DROP:
            action = FWP_ACTION_BLOCK;
            classify_output->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            break;
        }
    }
done:
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