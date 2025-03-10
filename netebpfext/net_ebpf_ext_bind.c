// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This file implements the BIND program type hook on eBPF for Windows.
 */

#include "ebpf_shared_framework.h"
#include "net_ebpf_ext_bind.h"

typedef struct _bind_context_header
{
    EBPF_CONTEXT_HEADER;
    bind_md_t context;
} bind_context_header_t;

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
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_bind_program_info,
    .context_create = _ebpf_bind_context_create,
    .context_destroy = _ebpf_bind_context_destroy,
    .required_irql = PASSIVE_LEVEL,
    .capabilities = {0},
};

// Set the program type as the provider module id.
NPI_MODULEID DECLSPEC_SELECTANY _ebpf_bind_program_info_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, EBPF_PROGRAM_TYPE_BIND_GUID};

static net_ebpf_extension_program_info_provider_t* _ebpf_bind_program_info_provider_context = NULL;

//
// Bind Hook NPI Provider.
//
ebpf_attach_provider_data_t _net_ebpf_bind_hook_provider_data = {
    EBPF_ATTACH_PROVIDER_DATA_HEADER, EBPF_PROGRAM_TYPE_BIND_GUID, BPF_ATTACH_TYPE_BIND, BPF_LINK_TYPE_PLAIN};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_bind_hook_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, EBPF_ATTACH_TYPE_BIND_GUID};

static net_ebpf_extension_hook_provider_t* _ebpf_bind_hook_provider_context = NULL;

//
// Client attach/detach handler routines.
//

static ebpf_result_t
_net_ebpf_ext_bind_validate_client_data(_In_ const ebpf_extension_data_t* client_data, _Out_ bool* is_wildcard)
{
    // Bind hook does not require any client data.
    UNREFERENCED_PARAMETER(client_data);
    *is_wildcard = FALSE;
    return EBPF_SUCCESS;
}

static ebpf_result_t
_net_ebpf_ext_bind_create_filter_context(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    net_ebpf_extension_wfp_filter_context_t* local_filter_context = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    result = net_ebpf_extension_wfp_filter_context_create(
        sizeof(net_ebpf_extension_wfp_filter_context_t), attaching_client, provider_context, &local_filter_context);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    local_filter_context->filter_ids_count = NET_EBPF_BIND_FILTER_COUNT;

    // Add WFP filters at appropriate layers and set the hook NPI client as the filter's raw context.
    result = net_ebpf_extension_add_wfp_filters(
        local_filter_context->wfp_engine_handle,
        EBPF_COUNT_OF(_net_ebpf_extension_bind_wfp_filter_parameters),
        _net_ebpf_extension_bind_wfp_filter_parameters,
        0,
        NULL,
        local_filter_context,
        &local_filter_context->filter_ids);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    *filter_context = (net_ebpf_extension_wfp_filter_context_t*)local_filter_context;
    local_filter_context = NULL;

Exit:
    if (local_filter_context != NULL) {
        CLEAN_UP_FILTER_CONTEXT(local_filter_context);
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static void
_net_ebpf_ext_bind_delete_filter_context(
    _In_opt_ _Frees_ptr_opt_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    NET_EBPF_EXT_LOG_ENTRY();

    if (filter_context == NULL) {
        goto Exit;
    }

    // Delete the WFP filters.
    net_ebpf_extension_delete_wfp_filters(
        filter_context->wfp_engine_handle, filter_context->filter_ids_count, filter_context->filter_ids);
    net_ebpf_extension_wfp_filter_context_cleanup((net_ebpf_extension_wfp_filter_context_t*)filter_context);

Exit:
    NET_EBPF_EXT_LOG_EXIT();
}

//
// NMR Registration Helper Routines.
//

NTSTATUS
net_ebpf_ext_bind_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    NET_EBPF_EXT_LOG_ENTRY();

    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_bind_program_info_provider_moduleid, &_ebpf_bind_program_data};
    const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_bind_hook_provider_moduleid, &_net_ebpf_bind_hook_provider_data};
    const net_ebpf_extension_hook_provider_dispatch_table_t dispatch_table = {
        .create_filter_context = _net_ebpf_ext_bind_create_filter_context,
        .delete_filter_context = _net_ebpf_ext_bind_delete_filter_context,
        .validate_client_data = _net_ebpf_ext_bind_validate_client_data};

    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_bind_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_BIND,
            "net_ebpf_extension_program_info_provider_register",
            status);
        goto Exit;
    }

    status = net_ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        &dispatch_table,
        ATTACH_CAPABILITY_SINGLE_ATTACH,
        NULL,
        &_ebpf_bind_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_BIND,
            "net_ebpf_extension_hook_provider_register",
            status);
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
    if (_ebpf_bind_hook_provider_context != NULL) {
        net_ebpf_extension_hook_provider_unregister(_ebpf_bind_hook_provider_context);
        _ebpf_bind_hook_provider_context = NULL;
    }
    if (_ebpf_bind_program_info_provider_context != NULL) {
        net_ebpf_extension_program_info_provider_unregister(_ebpf_bind_program_info_provider_context);
        _ebpf_bind_program_info_provider_context = NULL;
    }
}

//
// WFP Classify Callbacks.
//
static ebpf_result_t
_net_ebpf_ext_resource_validate_and_truncate_appid(bind_md_t* ctx, size_t app_id_size)
{
    // An empty app id is valid, but we should not process any truncation logic.
    if (app_id_size == 0) {
        return EBPF_SUCCESS;
    }
    // Ensure we have valid size for iterating and the pointers are valid.
    if ((app_id_size % sizeof(wchar_t) != 0) || (ctx->app_id_start == NULL) || (ctx->app_id_end == NULL)) {
        return EBPF_INVALID_ARGUMENT;
    }

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
    return EBPF_SUCCESS;
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
    ebpf_result_t program_result;
    bind_context_header_t context_header = {0};
    bind_md_t* ctx = &context_header.context;
    net_ebpf_extension_wfp_filter_context_t* filter_context = NULL;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        goto Exit;
    }

    // Note: This is intentionally not guarded by a lock as this is opportunistically checking if all the clients have
    // detached and the filter context is being deleted.
    if (filter_context->context_deleting) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_BIND,
            "net_ebpf_ext_resource_allocation_classify - Filter context deleting.",
            STATUS_INVALID_PARAMETER);
        goto Exit;
    }

    addr.sin_port =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT].value.uint16;
    addr.sin_addr.S_un.S_addr =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS].value.uint32;

    ctx->process_id = incoming_metadata_values->processId;
    memcpy(&ctx->socket_address, &addr, sizeof(addr));
    ctx->socket_address_length = sizeof(addr);
    ctx->operation = BIND_OPERATION_BIND;
    ctx->protocol = incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL].value.uint8;

    ctx->app_id_start =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_APP_ID].value.byteBlob->data;
    ctx->app_id_end =
        ctx->app_id_start +
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_APP_ID].value.byteBlob->size;

    result = _net_ebpf_ext_resource_validate_and_truncate_appid(
        ctx,
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_APP_ID].value.byteBlob->size);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    program_result = net_ebpf_extension_hook_invoke_programs(ctx, filter_context, &result);
    if (program_result == EBPF_OBJECT_NOT_FOUND) {
        // No program found.
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_BIND,
            "net_ebpf_ext_resource_allocation_classify - No programs found.");
        goto Exit;
    } else if (program_result != EBPF_SUCCESS) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_BIND,
            "net_ebpf_ext_resource_allocation_classify - net_ebpf_extension_hook_invoke_programs failed.",
            program_result);
        goto Exit;
    } else {
        switch (result) {
        case BIND_PERMIT:
        case BIND_REDIRECT:
            classify_output->actionType = FWP_ACTION_PERMIT;
            break;
        case BIND_DENY:
            classify_output->actionType = FWP_ACTION_BLOCK;
            classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            break;
        // If the program returns any other value, we will block the bind.
        default:
            classify_output->actionType = FWP_ACTION_BLOCK;
            classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            break;
        }
    }

Exit:
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
    bind_context_header_t context_header = {0};
    bind_md_t* ctx = &context_header.context;
    net_ebpf_extension_wfp_filter_context_t* filter_context = NULL;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        goto Exit;
    }

    // Note: This is intentionally not guarded by a lock as this is opportunistically checking if all the clients have
    // detached and the filter context is being deleted.
    if (filter_context->context_deleting) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_BIND,
            "net_ebpf_ext_resource_release_classify - Client detach detected.",
            STATUS_INVALID_PARAMETER);
        goto Exit;
    }

    addr.sin_port = incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_PORT].value.uint16;
    addr.sin_addr.S_un.S_addr =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_ADDRESS].value.uint32;

    ctx->process_id = incoming_metadata_values->processId;
    memcpy(&ctx->socket_address, &addr, sizeof(addr));
    ctx->socket_address_length = sizeof(addr);
    ctx->operation = BIND_OPERATION_UNBIND;
    ctx->protocol = incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_PROTOCOL].value.uint8;

    ctx->app_id_start =
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_APP_ID].value.byteBlob->data;
    ctx->app_id_end =
        ctx->app_id_start +
        incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_APP_ID].value.byteBlob->size;

    result = _net_ebpf_ext_resource_validate_and_truncate_appid(
        ctx, incoming_fixed_values->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_APP_ID].value.byteBlob->size);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Ignore the result of this call as we don't want to block the unbind.
    (void)net_ebpf_extension_hook_invoke_programs(ctx, filter_context, &result);

    classify_output->actionType = FWP_ACTION_PERMIT;

Exit:
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
    bind_context_header_t* bind_context_header = NULL;
    bind_md_t* bind_context = NULL;

    *context = NULL;

    if (context_in == NULL || context_size_in < sizeof(bind_md_t)) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_BIND, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    bind_context_header = (bind_context_header_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(bind_context_header_t), NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        NET_EBPF_EXT_TRACELOG_KEYWORD_BIND, bind_context_header, "bind_context_header", result);

    bind_context = &bind_context_header->context;
    // Copy the context from the caller.
    memcpy(bind_context, context_in, sizeof(bind_md_t));

    // Replace the app_id_start and app_id_end with pointers to data_in.
    bind_context->app_id_start = (uint8_t*)data_in;
    bind_context->app_id_end = (uint8_t*)data_in + data_size_in;

    result = _net_ebpf_ext_resource_validate_and_truncate_appid(bind_context, data_size_in);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    *context = bind_context;
    bind_context_header = NULL;
    result = EBPF_SUCCESS;

Exit:
    if (bind_context_header) {
        ExFreePool(bind_context_header);
        bind_context_header = NULL;
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
    bind_context_header_t* bind_context_header = NULL;

    if (!bind_context) {
        goto Exit;
    }

    bind_context_header = CONTAINING_RECORD(bind_context, bind_context_header_t, context);

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

    ExFreePool(bind_context_header);

Exit:
    NET_EBPF_EXT_LOG_EXIT();
}
