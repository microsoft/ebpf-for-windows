// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file This file implements the hook for the CGROUP_SOCK_ADDR program type and associated attach types, on eBPF for
 * Windows.
 *
 */

#define INITGUID

#include "net_ebpf_ext_sock_addr.h"

//
// WFP filter related types & globals for SOCK_ADDR hook.
//

const ebpf_attach_type_t* _net_ebpf_extension_sock_addr_attach_types[] = {
    &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
    &EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT,
    &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT,
    &EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT};

#define NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT EBPF_COUNT_OF(_net_ebpf_extension_sock_addr_attach_types)

const net_ebpf_extension_wfp_filter_parameters_t _net_ebpf_extension_sock_addr_wfp_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
     &EBPF_HOOK_ALE_AUTH_CONNECT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
     &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
     &EBPF_HOOK_ALE_AUTH_CONNECT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
     &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

typedef struct _net_ebpf_extension_sock_addr_wfp_filter_context
{
    const net_ebpf_extension_hook_client_t* client_context;
    uint32_t compartment_id;
    uint64_t filter_id;
} net_ebpf_extension_sock_addr_wfp_filter_context_t;

//
// SOCK_ADDR Program Information NPI Provider.
//

static ebpf_program_data_t _ebpf_sock_addr_program_data = {&_ebpf_sock_addr_program_info, NULL};

static ebpf_extension_data_t _ebpf_sock_addr_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_sock_addr_program_data), &_ebpf_sock_addr_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_addr_program_info_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static net_ebpf_extension_program_info_provider_t* _ebpf_sock_addr_program_info_provider_context = NULL;

//
// SOCK_ADDR Hook NPI Provider.
//

ebpf_attach_provider_data_t _net_ebpf_sock_addr_hook_provider_data;

ebpf_extension_data_t _net_ebpf_extension_sock_addr_hook_provider_data = {
    EBPF_ATTACH_PROVIDER_DATA_VERSION,
    sizeof(_net_ebpf_sock_addr_hook_provider_data),
    &_net_ebpf_sock_addr_hook_provider_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_addr_hook_provider_moduleid[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};

static net_ebpf_extension_hook_provider_t*
    _ebpf_sock_addr_hook_provider_context[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};

//
// NMR Registration Helper Routines.
//

static ebpf_result_t
net_ebpf_extension_sock_addr_on_client_attach(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    const ebpf_extension_data_t* client_data = net_ebpf_extension_hook_client_get_client_data(attaching_client);
    uint32_t compartment_id;
    uint32_t wild_card_compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    net_ebpf_extension_wfp_filter_parameters_t* filter_parameters = NULL;
    FWPM_FILTER_CONDITION condition = {0};
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;

    // SOCK_ADDR hook clients must always provide data.
    if (client_data == NULL) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (client_data->size > 0) {
        if ((client_data->size != sizeof(uint32_t)) || (client_data->data == NULL)) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
        compartment_id = *(uint32_t*)client_data->data;
    } else {
        // If the client did not specify any attach parameters, we treat that as a wildcard interface index.
        compartment_id = wild_card_compartment_id;
    }

    result = net_ebpf_extension_hook_check_attach_parameter(
        sizeof(compartment_id),
        &compartment_id,
        &wild_card_compartment_id,
        (net_ebpf_extension_hook_provider_t*)provider_context);
    if (result != EBPF_SUCCESS)
        goto Exit;

    if (client_data->data != NULL)
        compartment_id = *(uint32_t*)client_data->data;

    // Set compartment id (if not UNSPECIFIED_COMPARTMENT_ID) as WFP filter condition.
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID) {
        condition.fieldKey = FWPM_CONDITION_COMPARTMENT_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = compartment_id;
    }

    // Allocate buffer for WFP filter context.
    filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_sock_addr_wfp_filter_context_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (filter_context == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(filter_context, 0, sizeof(net_ebpf_extension_sock_addr_wfp_filter_context_t));
    filter_context->client_context = attaching_client;
    filter_context->compartment_id = compartment_id;

    // Get the WFP filter parameters for this hook type.
    filter_parameters =
        (net_ebpf_extension_wfp_filter_parameters_t*)net_ebpf_extension_hook_provider_get_custom_data(provider_context);
    ASSERT(filter_parameters != NULL);

    // Add a single WFP filter at the WFP layer corresponding to the hook type, and set the hook NPI client as the
    // filter's raw context.
    result = net_ebpf_extension_add_wfp_filters(
        1, // filter_count
        filter_parameters,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? 0 : 1,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? NULL : &condition,
        filter_context,
        &filter_context->filter_id);
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
_net_ebpf_extension_sock_addr_on_client_detach(_In_ const net_ebpf_extension_hook_client_t* detaching_client)
{
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context =
        (net_ebpf_extension_sock_addr_wfp_filter_context_t*)net_ebpf_extension_hook_client_get_provider_data(
            detaching_client);
    ASSERT(filter_context != NULL);
    net_ebpf_extension_delete_wfp_filters(1, &filter_context->filter_id);
    ExFreePool(filter_context);
}

NTSTATUS
net_ebpf_ext_sock_addr_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;
    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_sock_addr_program_info_provider_moduleid, &_ebpf_sock_addr_program_info_provider_data};

    _ebpf_sock_addr_program_info.program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
    // Set the program type as the provider module id.
    _ebpf_sock_addr_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_sock_addr_program_info_provider_context);
    if (status != STATUS_SUCCESS)
        goto Exit;

    _net_ebpf_sock_addr_hook_provider_data.supported_program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
    for (int i = 0; i < NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT; i++) {
        const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
            &_ebpf_sock_addr_hook_provider_moduleid[i],
            &_net_ebpf_extension_sock_addr_hook_provider_data,
            EXECUTION_DISPATCH};

        // Set the attach type as the provider module id.
        _ebpf_sock_addr_hook_provider_moduleid[i].Length = sizeof(NPI_MODULEID);
        _ebpf_sock_addr_hook_provider_moduleid[i].Type = MIT_GUID;
        _ebpf_sock_addr_hook_provider_moduleid[i].Guid = *_net_ebpf_extension_sock_addr_attach_types[i];
        // Register the provider context and pass the pointer to the WFP filter parameters
        // corresponding to this hook type as custom data.
        status = net_ebpf_extension_hook_provider_register(
            &hook_provider_parameters,
            net_ebpf_extension_sock_addr_on_client_attach,
            _net_ebpf_extension_sock_addr_on_client_detach,
            &_net_ebpf_extension_sock_addr_wfp_filter_parameters[i],
            &_ebpf_sock_addr_hook_provider_context[i]);
    }

    if (status != EBPF_SUCCESS)
        goto Exit;

Exit:
    return status;
}

void
net_ebpf_ext_sock_addr_unregister_providers()
{
    for (int i = 0; i < NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT; i++)
        net_ebpf_extension_hook_provider_unregister(_ebpf_sock_addr_hook_provider_context[i]);
    net_ebpf_extension_program_info_provider_unregister(_ebpf_sock_addr_program_info_provider_context);
}

typedef enum _net_ebpf_extension_sock_addr_hook_id
{
    EBPF_HOOK_SOCK_ADDR_CONNECT_V4 = 0,
    EBPF_HOOK_SOCK_ADDR_RECV_ACCEPT_V4,
    EBPF_HOOK_SOCK_ADDR_CONNECT_V6,
    EBPF_HOOK_SOCK_ADDR_RECV_ACCEPT_V6,
} net_ebpf_extension_sock_addr_hook_id_t;

static net_ebpf_extension_sock_addr_hook_id_t
_net_ebpf_extension_sock_addr_get_hook_id_from_wfp_layer_id(uint16_t wfp_layer_id)
{
    net_ebpf_extension_sock_addr_hook_id_t hook_id = 0;
    ASSERT(
        ((wfp_layer_id == FWPS_LAYER_ALE_AUTH_CONNECT_V4) || (wfp_layer_id == FWPS_LAYER_ALE_AUTH_CONNECT_V6) ||
         (wfp_layer_id == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4) || (wfp_layer_id == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6)));

    switch (wfp_layer_id) {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        hook_id = EBPF_HOOK_SOCK_ADDR_CONNECT_V4;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        hook_id = EBPF_HOOK_SOCK_ADDR_RECV_ACCEPT_V4;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        hook_id = EBPF_HOOK_SOCK_ADDR_CONNECT_V6;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        hook_id = EBPF_HOOK_SOCK_ADDR_RECV_ACCEPT_V6;
        break;
    }

    return hook_id;
}

typedef enum _net_ebpf_extension_sock_addr_connection_direction
{
    EBPF_HOOK_SOCK_ADDR_INGRESS = 0,
    EBPF_HOOK_SOCK_ADDR_EGRESS
} net_ebpf_extension_sock_addr_connection_direction_t;

static net_ebpf_extension_sock_addr_connection_direction_t
_net_ebpf_extension_sock_addr_get_connection_direction_from_hook_id(net_ebpf_extension_sock_addr_hook_id_t hook_id)
{
    return ((hook_id == EBPF_HOOK_SOCK_ADDR_CONNECT_V4) || (hook_id == EBPF_HOOK_SOCK_ADDR_CONNECT_V6))
               ? EBPF_HOOK_SOCK_ADDR_EGRESS
               : EBPF_HOOK_SOCK_ADDR_INGRESS;
}

typedef struct _wfp_connection_fields
{
    uint16_t local_ip_address_field;
    uint16_t local_port_field;
    uint16_t remote_ip_address_field;
    uint16_t remote_port_field;
    uint16_t protocol_field;
    uint16_t compartment_id_field;
} wfp_connection_fields_t;

wfp_connection_fields_t wfp_connection_fields[] = {
    // EBPF_HOOK_SOCK_ADDR_CONNECT_V4
    {FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_COMPARTMENT_ID},
    // EBPF_HOOK_SOCK_ADDR_RECV_ACCEPT_V4
    {FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_COMPARTMENT_ID},
    // EBPF_HOOK_SOCK_ADDR_CONNECT_V6
    {FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_COMPARTMENT_ID},
    // EBPF_HOOK_SOCK_ADDR_RECV_ACCEPT_V6
    {FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_COMPARTMENT_ID}};

static void
_net_ebpf_extension_sock_addr_copy_wfp_connection_fields(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values, _Out_ bpf_sock_addr_t* sock_addr_ctx)
{
    net_ebpf_extension_sock_addr_hook_id_t hook_id =
        _net_ebpf_extension_sock_addr_get_hook_id_from_wfp_layer_id(incoming_fixed_values->layerId);
    net_ebpf_extension_sock_addr_connection_direction_t direction =
        _net_ebpf_extension_sock_addr_get_connection_direction_from_hook_id(hook_id);
    wfp_connection_fields_t* fields = &wfp_connection_fields[hook_id];

    uint16_t source_ip_address_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->local_ip_address_field : fields->remote_ip_address_field;
    uint16_t source_port_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->local_port_field : fields->remote_port_field;
    uint16_t destination_ip_address_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->remote_ip_address_field : fields->local_ip_address_field;
    uint16_t destination_port_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->remote_port_field : fields->local_port_field;

    FWPS_INCOMING_VALUE0* incoming_values = incoming_fixed_values->incomingValue;

    // Copy IP address fields.
    if ((hook_id == EBPF_HOOK_SOCK_ADDR_CONNECT_V4) || (hook_id == EBPF_HOOK_SOCK_ADDR_RECV_ACCEPT_V4)) {
        sock_addr_ctx->family = AF_INET;
        sock_addr_ctx->msg_src_ip4 = incoming_values[source_ip_address_field].value.uint32;
        sock_addr_ctx->user_ip4 = incoming_values[destination_ip_address_field].value.uint32;
    } else {
        sock_addr_ctx->family = AF_INET6;
        RtlCopyMemory(
            sock_addr_ctx->msg_src_ip6,
            incoming_values[source_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
        RtlCopyMemory(
            sock_addr_ctx->user_ip6,
            incoming_values[destination_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
    }
    sock_addr_ctx->msg_src_port = incoming_values[source_port_field].value.uint16;
    sock_addr_ctx->user_port = incoming_values[destination_port_field].value.uint16;
    sock_addr_ctx->protocol = incoming_values[fields->protocol_field].value.uint8;
    sock_addr_ctx->compartment_id = incoming_values[fields->compartment_id_field].value.uint32;
}

//
// WFP callout callback function.
//
void
net_ebpf_extension_sock_addr_authorize_connection_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    uint32_t result;
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_hook_client_t* attached_client = NULL;
    net_ebpf_extension_hook_execution_t execution_type =
        (KeGetCurrentIrql() < DISPATCH_LEVEL) ? EXECUTION_PASSIVE : EXECUTION_DISPATCH;
    bpf_sock_addr_t sock_addr_ctx = {0};
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;

    UNREFERENCED_PARAMETER(incoming_metadata_values);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->client_context;
    ASSERT(attached_client != NULL);
    if (attached_client == NULL)
        goto Exit;

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client, execution_type))
        goto Exit;

    _net_ebpf_extension_sock_addr_copy_wfp_connection_fields(incoming_fixed_values, &sock_addr_ctx);

    compartment_id = filter_context->compartment_id;
    ASSERT((compartment_id == UNSPECIFIED_COMPARTMENT_ID) || (compartment_id == sock_addr_ctx.compartment_id));
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID && compartment_id != sock_addr_ctx.compartment_id) {
        // The client is not interested in this compartment Id.
        goto Exit;
    }

    if (net_ebpf_extension_hook_invoke_program(attached_client, &sock_addr_ctx, &result) != EBPF_SUCCESS)
        goto Exit;

    classify_output->actionType = (result == BPF_SOCK_ADDR_VERDICT_PROCEED) ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;

Exit:
    if (attached_client)
        net_ebpf_extension_hook_client_leave_rundown(attached_client, execution_type);
}