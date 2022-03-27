// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file This file implements the BIND program type hook on eBPF for Windows.
 *
 */

#define INITGUID

#include "net_ebpf_ext_bind.h"

//
// WFP bind layer filter related globals.
//

const net_ebpf_extension_wfp_filter_parameters_t _net_ebpf_extension_bind_wfp_filter_parameters[] = {
    {&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
     &EBPF_HOOK_ALE_RESOURCE_ALLOC_V4_CALLOUT,
     L"net eBPF bind hook",
     L"net eBPF bind hook WFP filter"},
    {&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
     &EBPF_HOOK_ALE_RESOURCE_ALLOC_V6_CALLOUT,
     L"net eBPF bind hook",
     L"net eBPF bind hook WFP filter"},
    {&FWPM_LAYER_ALE_RESOURCE_RELEASE_V4,
     &EBPF_HOOK_ALE_RESOURCE_RELEASE_V4_CALLOUT,
     L"net eBPF bind hook",
     L"net eBPF bind hook WFP filter"},
    {&FWPM_LAYER_ALE_RESOURCE_RELEASE_V6,
     &EBPF_HOOK_ALE_RESOURCE_RELEASE_V6_CALLOUT,
     L"net eBPF bind hook",
     L"net eBPF bind hook WFP filter"}};

#define NET_EBPF_BIND_FILTER_COUNT EBPF_COUNT_OF(_net_ebpf_extension_bind_wfp_filter_parameters)

uint64_t _net_ebpf_extension_bind_wfp_filter_ids[NET_EBPF_BIND_FILTER_COUNT] = {0};

//
// Bind Program Information NPI Provider.
//
static ebpf_context_descriptor_t _ebpf_bind_context_descriptor = {
    sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};
static ebpf_program_info_t _ebpf_bind_program_info = {{"bind", &_ebpf_bind_context_descriptor, {0}}, 0, NULL};

static ebpf_program_data_t _ebpf_bind_program_data = {&_ebpf_bind_program_info, NULL};

static ebpf_extension_data_t _ebpf_bind_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_bind_program_data), &_ebpf_bind_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_bind_program_info_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static net_ebpf_extension_program_info_provider_t* _ebpf_bind_program_info_provider_context = NULL;

//
// Bind Hook NPI Provider.
//
ebpf_attach_provider_data_t _net_ebpf_bind_hook_provider_data;

ebpf_extension_data_t _net_ebpf_extension_bind_hook_provider_data = {
    EBPF_ATTACH_PROVIDER_DATA_VERSION, sizeof(_net_ebpf_bind_hook_provider_data), &_net_ebpf_bind_hook_provider_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_bind_hook_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static net_ebpf_extension_hook_provider_t* _ebpf_bind_hook_provider_context = NULL;

//
// Client attach/detach handler routines.
//

static ebpf_result_t
_net_ebpf_extension_bind_on_client_attach(_In_ const net_ebpf_extension_hook_client_t* attaching_client)
{
    ebpf_result_t result = EBPF_SUCCESS;

    // Bind hook allows only one client at a time.
    if (net_ebpf_extension_hook_get_next_attached_client(_ebpf_bind_hook_provider_context, NULL) != NULL) {
        result = EBPF_ACCESS_DENIED;
        goto Exit;
    }

    // Add WFP filters at appropriate layers and set the hook NPI client as the filter's raw context.
    result = net_ebpf_extension_add_wfp_filters(
        EBPF_COUNT_OF(_net_ebpf_extension_bind_wfp_filter_parameters),
        _net_ebpf_extension_bind_wfp_filter_parameters,
        0,
        NULL,
        attaching_client,
        _net_ebpf_extension_bind_wfp_filter_ids);
    if (result != EBPF_SUCCESS)
        goto Exit;

Exit:
    return result;
}

static void
_net_ebpf_extension_bind_on_client_detach(_In_ const net_ebpf_extension_hook_client_t* detaching_client)
{
    UNREFERENCED_PARAMETER(detaching_client);

    // Delete the WFP filters.
    net_ebpf_extension_delete_wfp_filters(NET_EBPF_BIND_FILTER_COUNT, _net_ebpf_extension_bind_wfp_filter_ids);
    memset(_net_ebpf_extension_bind_wfp_filter_ids, 0, sizeof(_net_ebpf_extension_bind_wfp_filter_ids));
}

//
// NMR Registration Helper Routines.
//

NTSTATUS
net_ebpf_ext_bind_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;
    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_bind_program_info_provider_moduleid, &_ebpf_bind_program_info_provider_data};
    const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_bind_hook_provider_moduleid, &_net_ebpf_extension_bind_hook_provider_data, EXECUTION_PASSIVE};

    _ebpf_bind_program_info.program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_BIND;
    // Set the program type as the provider module id.
    _ebpf_bind_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_BIND;
    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_bind_program_info_provider_context);
    if (status != STATUS_SUCCESS)
        goto Exit;

    _net_ebpf_bind_hook_provider_data.supported_program_type = EBPF_PROGRAM_TYPE_BIND;
    // Set the attach type as the provider module id.
    _ebpf_bind_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_BIND;
    status = net_ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        _net_ebpf_extension_bind_on_client_attach,
        _net_ebpf_extension_bind_on_client_detach,
        &_ebpf_bind_hook_provider_context);
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
    UNREFERENCED_PARAMETER(flow_context);

    attached_client = (net_ebpf_extension_hook_client_t*)filter->context;
    ASSERT(attached_client != NULL);
    if (attached_client == NULL)
        goto Exit;

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client, EXECUTION_PASSIVE)) {
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
        net_ebpf_extension_hook_client_leave_rundown(attached_client, EXECUTION_PASSIVE);
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
    UNREFERENCED_PARAMETER(flow_context);

    attached_client = (net_ebpf_extension_hook_client_t*)filter->context;
    ASSERT(attached_client != NULL);
    if (attached_client == NULL)
        goto Exit;

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client, EXECUTION_PASSIVE)) {
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
        net_ebpf_extension_hook_client_leave_rundown(attached_client, EXECUTION_PASSIVE);
    return;
}