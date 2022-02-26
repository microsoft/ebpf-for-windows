// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file This file implements the BIND program type hook on eBPF for Windows.
 *
 */

#define INITGUID

#include "net_ebpf_ext_prog_info_provider.h"

//
// Bind Program Information NPI Provider.
//
static ebpf_context_descriptor_t _ebpf_bind_context_descriptor = {
    sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};
static ebpf_program_info_t _ebpf_bind_program_info = {{"bind", &_ebpf_bind_context_descriptor, {0}}, 0, NULL};

static ebpf_program_data_t _ebpf_bind_program_data = {&_ebpf_bind_program_info, NULL};

static ebpf_extension_data_t _ebpf_bind_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_bind_program_data), &_ebpf_bind_program_data};

// Net eBPF Extension Bind Program Information NPI Provider Module GUID: 6c8d3dbd-f1e3-4c42-abb8-cf7f095c9df3
const NPI_MODULEID DECLSPEC_SELECTANY _ebpf_bind_program_info_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, {0x6c8d3dbd, 0xf1e3, 0x4c42, {0xab, 0xb8, 0xcf, 0x7f, 0x09, 0x5c, 0x9d, 0xf3}}};

const NPI_PROVIDER_CHARACTERISTICS _ebpf_bind_program_info_provider_characteristics = {
    0,
    sizeof(NPI_PROVIDER_CHARACTERISTICS),
    net_ebpf_extension_program_info_provider_attach_client,
    net_ebpf_extension_program_info_provider_detach_client,
    NULL,
    {0,
     sizeof(NPI_REGISTRATION_INSTANCE),
     &EBPF_PROGRAM_TYPE_BIND,
     &_ebpf_bind_program_info_provider_moduleid,
     0,
     &_ebpf_bind_program_info_provider_data},
};

static net_ebpf_extension_program_info_provider_t* _ebpf_bind_program_info_provider_context = NULL;

//
// Bind Hook NPI Provider.
//
ebpf_attach_provider_data_t _net_ebpf_bind_hook_provider_data;

ebpf_extension_data_t _net_ebpf_extension_bind_hook_provider_data = {
    EBPF_ATTACH_PROVIDER_DATA_VERSION, sizeof(_net_ebpf_bind_hook_provider_data), &_net_ebpf_bind_hook_provider_data};

// Net eBPF Extension Bind Hook NPI Provider Module GUID: eab8f3d9-ab6c-422e-994c-7a80943bc920
const NPI_MODULEID DECLSPEC_SELECTANY _ebpf_bind_hook_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, {0xeab8f3d9, 0xab6c, 0x422e, {0x99, 0x4c, 0x7a, 0x80, 0x94, 0x3b, 0xc9, 0x20}}};

const NPI_PROVIDER_CHARACTERISTICS _ebpf_bind_hook_provider_characteristics = {
    0,
    sizeof(NPI_PROVIDER_CHARACTERISTICS),
    net_ebpf_extension_hook_provider_attach_client,
    net_ebpf_extension_hook_provider_detach_client,
    NULL,
    {0,
     sizeof(NPI_REGISTRATION_INSTANCE),
     &EBPF_ATTACH_TYPE_BIND,
     &_ebpf_bind_hook_provider_moduleid,
     0,
     &_net_ebpf_extension_bind_hook_provider_data},
};

static net_ebpf_extension_hook_provider_t* _ebpf_bind_hook_provider_context = NULL;

//
// NMR Registration Helper Routines.
//

NTSTATUS
net_ebpf_ext_bind_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;
    _net_ebpf_bind_hook_provider_data.supported_program_type = EBPF_PROGRAM_TYPE_BIND;

    status = net_ebpf_extension_program_info_provider_register(
        &_ebpf_bind_program_info_provider_characteristics, &_ebpf_bind_program_info_provider_context);
    if (status != STATUS_SUCCESS)
        goto Exit;

    status = net_ebpf_extension_hook_provider_register(
        &_ebpf_bind_hook_provider_characteristics, EXECUTION_PASSIVE, &_ebpf_bind_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    return status;
}

void
net_ebpf_ext_bind_unregister_providers()
{
    net_ebpf_extension_hook_provider_unregister(_ebpf_bind_hook_provider_context);
    net_ebpf_extension_program_info_provider_unregister(_ebpf_bind_program_info_provider_context);
}

//
// WFP Classify Callbacks.
//

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

void
net_ebpf_ext_resource_allocation_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    SOCKADDR_IN addr = {AF_INET};
    uint32_t result;
    bind_md_t ctx;
    net_ebpf_extension_hook_client_t* attached_client = NULL;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flow_context);

    attached_client = net_ebpf_extension_get_attached_client(_ebpf_bind_hook_provider_context);
    if (attached_client == NULL)
        goto Exit;

    if (!net_ebpf_extension_attach_enter_rundown(attached_client, EXECUTION_PASSIVE)) {
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
    if (net_ebpf_extension_hook_invoke_program(attached_client, &ctx, &result) == EBPF_SUCCESS) {
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
    if (attached_client)
        net_ebpf_extension_attach_leave_rundown(attached_client, EXECUTION_PASSIVE);
    return;
}

void
net_ebpf_ext_resource_release_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    SOCKADDR_IN addr = {AF_INET};
    uint32_t result;
    bind_md_t ctx;
    net_ebpf_extension_hook_client_t* attached_client = NULL;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flow_context);

    attached_client = net_ebpf_extension_get_attached_client(_ebpf_bind_hook_provider_context);
    if (attached_client == NULL)
        goto Exit;

    if (!net_ebpf_extension_attach_enter_rundown(attached_client, EXECUTION_PASSIVE)) {
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

    net_ebpf_extension_hook_invoke_program(attached_client, &ctx, &result);

    classify_output->actionType = FWP_ACTION_PERMIT;

Exit:
    if (attached_client)
        net_ebpf_extension_attach_leave_rundown(attached_client, EXECUTION_PASSIVE);
    return;
}