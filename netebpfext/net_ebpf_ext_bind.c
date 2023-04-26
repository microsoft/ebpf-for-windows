// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This file implements the BIND program type hook on eBPF for Windows.
 */

#include "ebpf_store_helper.h"
#include "net_ebpf_ext_bind.h"

//
// WFP filter related globals for bind hook.
//

const net_ebpf_extension_wfp_filter_parameters_t _net_ebpf_extension_bind_wfp_filter_parameters[] = {
    {&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_RESOURCE_ALLOC_V4_CALLOUT,
     L"net eBPF bind hook",
     L"net eBPF bind hook WFP filter"},
    {&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_RESOURCE_ALLOC_V6_CALLOUT,
     L"net eBPF bind hook",
     L"net eBPF bind hook WFP filter"},
    {&FWPM_LAYER_ALE_RESOURCE_RELEASE_V4,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_RESOURCE_RELEASE_V4_CALLOUT,
     L"net eBPF bind hook",
     L"net eBPF bind hook WFP filter"},
    {&FWPM_LAYER_ALE_RESOURCE_RELEASE_V6,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_RESOURCE_RELEASE_V6_CALLOUT,
     L"net eBPF bind hook",
     L"net eBPF bind hook WFP filter"}};

#define NET_EBPF_BIND_FILTER_COUNT EBPF_COUNT_OF(_net_ebpf_extension_bind_wfp_filter_parameters)

static ebpf_result_t
_ebpf_bind_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_ebpf_bind_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

//
// Bind Program Information NPI Provider.
//
static ebpf_program_data_t _ebpf_bind_program_data = {
    .program_info = &_ebpf_bind_program_info,
    .context_create = _ebpf_bind_context_create,
    .context_destroy = _ebpf_bind_context_destroy,
    .required_irql = PASSIVE_LEVEL,
};

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
_net_ebpf_extension_bind_on_client_attach(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    net_ebpf_extension_wfp_filter_context_t* filter_context = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    // Bind hook allows only one client at a time.
    if (net_ebpf_extension_hook_get_next_attached_client((net_ebpf_extension_hook_provider_t*)provider_context, NULL) !=
        NULL) {
        result = EBPF_ACCESS_DENIED;
        goto Exit;
    }

    result = net_ebpf_extension_wfp_filter_context_create(
        sizeof(net_ebpf_extension_wfp_filter_context_t), attaching_client, &filter_context);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    filter_context->filter_ids_count = NET_EBPF_BIND_FILTER_COUNT;

    // Add WFP filters at appropriate layers and set the hook NPI client as the filter's raw context.
    result = net_ebpf_extension_add_wfp_filters(
        EBPF_COUNT_OF(_net_ebpf_extension_bind_wfp_filter_parameters),
        _net_ebpf_extension_bind_wfp_filter_parameters,
        0,
        NULL,
        filter_context,
        &filter_context->filter_ids);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Set the filter context as the client context's provider data.
    net_ebpf_extension_hook_client_set_provider_data(
        (net_ebpf_extension_hook_client_t*)attaching_client, filter_context);

Exit:
    if (result != EBPF_SUCCESS) {
        if (filter_context != NULL) {
            ExFreePool(filter_context);
        }
    }
    NET_EBPF_EXT_RETURN_RESULT(result);
}

static void
_net_ebpf_extension_bind_on_client_detach(_In_ const net_ebpf_extension_hook_client_t* detaching_client)
{
    net_ebpf_extension_wfp_filter_context_t* filter_context =
        (net_ebpf_extension_wfp_filter_context_t*)net_ebpf_extension_hook_client_get_provider_data(detaching_client);
    ASSERT(filter_context != NULL);

    // Delete the WFP filters.
    net_ebpf_extension_delete_wfp_filters(filter_context->filter_ids_count, filter_context->filter_ids);
    net_ebpf_extension_wfp_filter_context_cleanup((net_ebpf_extension_wfp_filter_context_t*)filter_context);
}

//
// NMR Registration Helper Routines.
//

static NTSTATUS
_net_ebpf_bind_update_store_entries()
{
    NTSTATUS status;

    // Update section information.
    uint32_t section_info_count = sizeof(_ebpf_bind_section_info) / sizeof(ebpf_program_section_info_t);
    status = _ebpf_store_update_section_information(&_ebpf_bind_section_info[0], section_info_count);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Update program information.
    status = _ebpf_store_update_program_information(&_ebpf_bind_program_info, 1);

    return status;
}

NTSTATUS
net_ebpf_ext_bind_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    status = _net_ebpf_bind_update_store_entries();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_bind_program_info_provider_moduleid, &_ebpf_bind_program_info_provider_data};
    const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_bind_hook_provider_moduleid, &_net_ebpf_extension_bind_hook_provider_data};

    NET_EBPF_EXT_LOG_ENTRY();

    // Set the program type as the provider module id.
    _ebpf_bind_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_BIND;
    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_bind_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    _net_ebpf_bind_hook_provider_data.supported_program_type = EBPF_PROGRAM_TYPE_BIND;
    // Set the attach type as the provider module id.
    _ebpf_bind_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_BIND;
    _net_ebpf_bind_hook_provider_data.bpf_attach_type = BPF_ATTACH_TYPE_BIND;
    _net_ebpf_bind_hook_provider_data.link_type = BPF_LINK_TYPE_PLAIN;
    status = net_ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        _net_ebpf_extension_bind_on_client_attach,
        _net_ebpf_extension_bind_on_client_detach,
        NULL,
        &_ebpf_bind_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        net_ebpf_ext_bind_unregister_providers();
    }
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_bind_unregister_providers()
{
    if (_ebpf_bind_hook_provider_context) {
        net_ebpf_extension_hook_provider_unregister(_ebpf_bind_hook_provider_context);
        _ebpf_bind_hook_provider_context = NULL;
    }
    if (_ebpf_bind_program_info_provider_context) {
        net_ebpf_extension_program_info_provider_unregister(_ebpf_bind_program_info_provider_context);
        _ebpf_bind_program_info_provider_context = NULL;
    }
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
    net_ebpf_extension_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_hook_client_t* attached_client = NULL;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        goto Exit;
    }

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->client_context;
    if (attached_client == NULL) {
        goto Exit;
    }

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client)) {
        attached_client = NULL;
        goto Exit;
    }

    addr.sin_port =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT].value.uint16;
    addr.sin_addr.S_un.S_addr =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS].value.uint32;

    ctx.process_id = incoming_metadata_values->processId;
    memcpy(&ctx.socket_address, &addr, sizeof(addr));
    ctx.socket_address_length = sizeof(addr);
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
            classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            break;
        }
    }

Exit:
    if (attached_client) {
        net_ebpf_extension_hook_client_leave_rundown(attached_client);
    }
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
    net_ebpf_extension_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_hook_client_t* attached_client = NULL;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        goto Exit;
    }

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->client_context;
    if (attached_client == NULL) {
        goto Exit;
    }

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client)) {
        attached_client = NULL;
        goto Exit;
    }

    addr.sin_port = incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_PORT].value.uint16;
    addr.sin_addr.S_un.S_addr =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_ADDRESS].value.uint32;

    ctx.process_id = incoming_metadata_values->processId;
    memcpy(&ctx.socket_address, &addr, sizeof(addr));
    ctx.socket_address_length = sizeof(addr);
    ctx.operation = BIND_OPERATION_UNBIND;
    ctx.protocol = incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_PROTOCOL].value.uint8;

    ctx.app_id_start =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_APP_ID].value.byteBlob->data;
    ctx.app_id_end =
        ctx.app_id_start +
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_APP_ID].value.byteBlob->size;

    _net_ebpf_ext_resource_truncate_appid(&ctx);

    // Ignore the result of this call as we don't want to block the unbind.
    (void)net_ebpf_extension_hook_invoke_program(attached_client, &ctx, &result);

    classify_output->actionType = FWP_ACTION_PERMIT;

Exit:
    if (attached_client) {
        net_ebpf_extension_hook_client_leave_rundown(attached_client);
    }
    return;
}

static ebpf_result_t
_ebpf_bind_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    NET_EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result;
    bind_md_t* bind_context = NULL;

    *context = NULL;

    if (context_in == NULL || context_size_in < sizeof(bind_md_t)) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    bind_context =
        (bind_md_t*)ExAllocatePoolUninitialized(NonPagedPool, sizeof(bind_md_t), NET_EBPF_EXTENSION_POOL_TAG);

    if (!bind_context) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Copy the context from the caller.
    memcpy(bind_context, context_in, sizeof(bind_md_t));

    // Replace the app_id_start and app_id_end with pointers to data_in.
    bind_context->app_id_start = (uint8_t*)data_in;
    bind_context->app_id_end = (uint8_t*)data_in + data_size_in;

    *context = bind_context;
    bind_context = NULL;
    result = EBPF_SUCCESS;
Exit:
    if (bind_context) {
        ExFreePool(bind_context);
        bind_context = NULL;
    }
    NET_EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_bind_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    NET_EBPF_EXT_LOG_ENTRY();

    bind_md_t* bind_context = (bind_md_t*)context;
    bind_md_t* bind_context_out = (bind_md_t*)context_out;

    if (!bind_context) {
        return;
    }

    if (context_out != NULL && *context_size_out >= sizeof(bind_md_t)) {
        // Copy the context to the caller.
        memcpy(bind_context_out, bind_context, sizeof(bind_md_t));

        // Zero out the app_id_start and app_id_end.
        bind_context_out->app_id_start = 0;
        bind_context_out->app_id_end = 0;
        *context_size_out = sizeof(bind_md_t);
    } else {
        *context_size_out = 0;
    }

    // Copy the app_id to the data_out.
    if (data_out != NULL && *data_size_out >= (size_t)(bind_context->app_id_end - bind_context->app_id_start)) {
        memcpy(data_out, bind_context->app_id_start, bind_context->app_id_end - bind_context->app_id_start);
        *data_size_out = bind_context->app_id_end - bind_context->app_id_start;
    } else {
        *data_size_out = 0;
    }

    ExFreePool(bind_context);
    NET_EBPF_EXT_LOG_FUNCTION_SUCCESS();
}
