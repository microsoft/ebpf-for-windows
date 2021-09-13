// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file This file implements the BIND program type hook on eBPF for Windows.
 *
 */

#define INITGUID

// ebpf_bind_program_data.h has generated
// headers. encode_program_info generates them from the structs
// in ebpf_nethooks.h. This workaround exists due to the inability
// to call RPC serialization services from kernel mode. Once we switch
// to a different serializer, we can get rid of this workaround.
#include "ebpf_bind_program_data.h"

#include "net_ebpf_ext.h"

static ebpf_ext_attach_hook_provider_registration_t* _ebpf_bind_hook_provider_registration = NULL;
static ebpf_extension_provider_t* _ebpf_bind_program_info_provider = NULL;

static ebpf_context_descriptor_t _ebpf_bind_context_descriptor = {
    sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};
static ebpf_program_info_t _ebpf_bind_program_info = {{"bind", &_ebpf_bind_context_descriptor, {0}}, 0, NULL};

static ebpf_program_data_t _ebpf_bind_program_data = {&_ebpf_bind_program_info, NULL};

static ebpf_extension_data_t _ebpf_bind_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_bind_program_data), &_ebpf_bind_program_data};

// b9707e04-8127-4c72-833e-05b1fb439496
DEFINE_GUID(EBPF_ATTACH_TYPE_BIND, 0xb9707e04, 0x8127, 0x4c72, 0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96);

// 608c517c-6c52-0x4a26-b677-bb01c34425adf
DEFINE_GUID(EBPF_PROGRAM_TYPE_BIND, 0x608c517c, 0x6c52, 0x4a26, 0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf);

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

static void
_net_ebpf_ext_bind_hook_provider_unregister()
{
    ebpf_ext_attach_unregister_provider(_ebpf_bind_hook_provider_registration);
}

static NTSTATUS
_net_ebpf_ext_bind_hook_provider_register()
{
    ebpf_result_t return_value;

    return_value = ebpf_ext_attach_register_provider(
        &EBPF_PROGRAM_TYPE_BIND,
        &EBPF_ATTACH_TYPE_BIND,
        EBPF_EXT_HOOK_EXECUTION_PASSIVE,
        &_ebpf_bind_hook_provider_registration);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    if (return_value != EBPF_SUCCESS) {
        _net_ebpf_ext_bind_hook_provider_unregister();
        return STATUS_UNSUCCESSFUL;
    } else
        return STATUS_SUCCESS;
}

static void
_net_ebpf_ext_bind_program_info_provider_unregister()
{
    ebpf_provider_unload(_ebpf_bind_program_info_provider);
}

static NTSTATUS
_net_ebpf_ext_bind_program_info_provider_register()
{
    ebpf_result_t return_value;
    ebpf_extension_data_t* provider_data;
    ebpf_program_data_t* program_data;

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
        _net_ebpf_ext_bind_program_info_provider_unregister();
        return STATUS_UNSUCCESSFUL;
    } else
        return STATUS_SUCCESS;
}

NTSTATUS
net_ebpf_ext_bind_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    status = _net_ebpf_ext_bind_program_info_provider_register();
    if (status != STATUS_SUCCESS)
        goto Exit;

    status = _net_ebpf_ext_bind_hook_provider_register();
    if (status != STATUS_SUCCESS)
        goto Exit;

Exit:
    return status;
}

void
net_ebpf_ext_bind_unregister_providers()
{
    _net_ebpf_ext_bind_hook_provider_unregister();
    _net_ebpf_ext_bind_program_info_provider_unregister();
}