// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/*
 * @file
 * @brief This file implements the hook for the SOCK_OPS program type and associated attach types, on eBPF for
 * Windows.
 *
 */

#include "ebpf_store_helper.h"
#include "net_ebpf_ext_sock_ops.h"

//
// WFP related types & globals for SOCK_OPS hook.
//

struct _net_ebpf_extension_sock_ops_wfp_filter_context;

/**
 * @brief Custom context associated with WFP flows that are notified to eBPF programs.
 */
typedef struct _net_ebpf_extension_sock_ops_wfp_flow_context
{
    LIST_ENTRY link;                                         ///< Link to next flow context.
    net_ebpf_extension_flow_context_parameters_t parameters; ///< WFP flow parameters.
    struct _net_ebpf_extension_sock_ops_wfp_filter_context*
        filter_context;       ///< WFP filter context associated with this flow.
    bool client_detached : 1; ///< Flag indicating that the hook client has detached.
    bpf_sock_ops_t context;   ///< sock_ops context.
} net_ebpf_extension_sock_ops_wfp_flow_context_t;

typedef struct _net_ebpf_extension_sock_ops_wfp_flow_context_list
{
    uint32_t count;       ///< Number of flow contexts in the list.
    LIST_ENTRY list_head; ///< Head to the list of WFP flow contexts.
} net_ebpf_extension_sock_ops_wfp_flow_context_list_t;

const net_ebpf_extension_wfp_filter_parameters_t _net_ebpf_extension_sock_ops_wfp_filter_parameters[] = {
    {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4_CALLOUT,
     L"net eBPF sock_ops hook",
     L"net eBPF sock_ops hook WFP filter"},
    {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6_CALLOUT,
     L"net eBPF sock_ops hook",
     L"net eBPF sock_ops hook WFP filter"}};

#define NET_EBPF_SOCK_OPS_FILTER_COUNT EBPF_COUNT_OF(_net_ebpf_extension_sock_ops_wfp_filter_parameters)

typedef struct _net_ebpf_extension_sock_ops_wfp_filter_context
{
    net_ebpf_extension_wfp_filter_context_t base;
    uint32_t compartment_id; ///< Compartment Id condition value for the filters (if any).
    KSPIN_LOCK lock;         ///< Lock for synchronization.
    _Guarded_by_(lock) net_ebpf_extension_sock_ops_wfp_flow_context_list_t
        flow_context_list; ///< List of flow contexts associated with WFP flows.
} net_ebpf_extension_sock_ops_wfp_filter_context_t;

//
// SOCK_OPS Program Information NPI Provider.
//

static ebpf_result_t
_ebpf_sock_ops_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_ebpf_sock_ops_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

static ebpf_program_data_t _ebpf_sock_ops_program_data = {
    .program_info = &_ebpf_sock_ops_program_info,
    .context_create = &_ebpf_sock_ops_context_create,
    .context_destroy = &_ebpf_sock_ops_context_destroy};

static ebpf_extension_data_t _ebpf_sock_ops_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_sock_ops_program_data), &_ebpf_sock_ops_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_ops_program_info_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static net_ebpf_extension_program_info_provider_t* _ebpf_sock_ops_program_info_provider_context = NULL;

//
// SOCK_OPS Hook NPI Provider.
//

ebpf_attach_provider_data_t _net_ebpf_sock_ops_hook_provider_data;

ebpf_extension_data_t _net_ebpf_extension_sock_ops_hook_provider_data = {
    EBPF_ATTACH_PROVIDER_DATA_VERSION,
    sizeof(_net_ebpf_sock_ops_hook_provider_data),
    &_net_ebpf_sock_ops_hook_provider_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_ops_hook_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static net_ebpf_extension_hook_provider_t* _ebpf_sock_ops_hook_provider_context = NULL;

//
// NMR Registration Helper Routines.
//

static ebpf_result_t
net_ebpf_extension_sock_ops_on_client_attach(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    const ebpf_extension_data_t* client_data = net_ebpf_extension_hook_client_get_client_data(attaching_client);
    uint32_t compartment_id;
    uint32_t wild_card_compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    uint32_t filter_count;
    FWPM_FILTER_CONDITION condition = {0};
    net_ebpf_extension_sock_ops_wfp_filter_context_t* filter_context = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    // SOCK_OPS hook clients must always provide data.
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
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (client_data->data != NULL) {
        compartment_id = *(uint32_t*)client_data->data;
    }

    // Set compartment id (if not UNSPECIFIED_COMPARTMENT_ID) as WFP filter condition.
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID) {
        condition.fieldKey = FWPM_CONDITION_COMPARTMENT_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = compartment_id;
    }

    result = net_ebpf_extension_wfp_filter_context_create(
        sizeof(net_ebpf_extension_sock_ops_wfp_filter_context_t),
        attaching_client,
        (net_ebpf_extension_wfp_filter_context_t**)&filter_context);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    filter_context->compartment_id = compartment_id;
    filter_context->base.filter_ids_count = NET_EBPF_SOCK_OPS_FILTER_COUNT;
    KeInitializeSpinLock(&filter_context->lock);
    InitializeListHead(&filter_context->flow_context_list.list_head);

    // Add WFP filters at appropriate layers and set the hook NPI client as the filter's raw context.
    filter_count = NET_EBPF_SOCK_OPS_FILTER_COUNT;
    result = net_ebpf_extension_add_wfp_filters(
        filter_count,
        _net_ebpf_extension_sock_ops_wfp_filter_parameters,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? 0 : 1,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? NULL : &condition,
        (net_ebpf_extension_wfp_filter_context_t*)filter_context,
        &filter_context->base.filter_ids);
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
_net_ebpf_extension_sock_ops_on_client_detach(_In_ const net_ebpf_extension_hook_client_t* detaching_client)
{
    net_ebpf_extension_sock_ops_wfp_filter_context_t* filter_context =
        (net_ebpf_extension_sock_ops_wfp_filter_context_t*)net_ebpf_extension_hook_client_get_provider_data(
            detaching_client);
    KIRQL irql;
    LIST_ENTRY local_list_head;

    ASSERT(filter_context != NULL);
    InitializeListHead(&local_list_head);
    net_ebpf_extension_delete_wfp_filters(filter_context->base.filter_ids_count, filter_context->base.filter_ids);

    KeAcquireSpinLock(&filter_context->lock, &irql);
    if (filter_context->flow_context_list.count > 0) {

        LIST_ENTRY* entry = filter_context->flow_context_list.list_head.Flink;
        RemoveEntryList(&filter_context->flow_context_list.list_head);
        InitializeListHead(&filter_context->flow_context_list.list_head);
        AppendTailList(&local_list_head, entry);

        filter_context->flow_context_list.count = 0;
    }
    KeReleaseSpinLock(&filter_context->lock, irql);

    // Remove the flow context associated with the WFP flows.
    while (!IsListEmpty(&local_list_head)) {
        LIST_ENTRY* entry = RemoveHeadList(&local_list_head);
        InitializeListHead(entry);
        net_ebpf_extension_sock_ops_wfp_flow_context_t* flow_context =
            CONTAINING_RECORD(entry, net_ebpf_extension_sock_ops_wfp_flow_context_t, link);
        flow_context->client_detached = TRUE;

        net_ebpf_extension_flow_context_parameters_t* flow_parameters = &flow_context->parameters;

        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowremovecontext0
        // Calling FwpsFlowRemoveContext may cause the flowDeleteFn callback on the callout to be invoked synchronously.
        // The net_ebpf_extension_sock_ops_flow_delete function frees the flow context memory and
        // releases reference on the filter_context.
#pragma warning(push)
#pragma warning(disable : 4189) // 'status': local variable is initialized but not referenced
        NTSTATUS status =
            FwpsFlowRemoveContext(flow_parameters->flow_id, flow_parameters->layer_id, flow_parameters->callout_id);
        ASSERT(status == STATUS_SUCCESS);
#pragma warning(pop)
    }

    net_ebpf_extension_wfp_filter_context_cleanup((net_ebpf_extension_wfp_filter_context_t*)filter_context);
}

static NTSTATUS
_net_ebpf_sock_ops_update_store_entries()
{
    NTSTATUS status;

    // Update section information.
    uint32_t section_info_count = sizeof(_ebpf_sock_ops_section_info) / sizeof(ebpf_program_section_info_t);
    status = _ebpf_store_update_section_information(&_ebpf_sock_ops_section_info[0], section_info_count);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Update program information.
    status = _ebpf_store_update_program_information(&_ebpf_sock_ops_program_info, 1);

    return status;
}

NTSTATUS
net_ebpf_ext_sock_ops_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;
    const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_sock_ops_hook_provider_moduleid, &_net_ebpf_extension_sock_ops_hook_provider_data};

    status = _net_ebpf_sock_ops_update_store_entries();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_sock_ops_program_info_provider_moduleid, &_ebpf_sock_ops_program_info_provider_data};

    NET_EBPF_EXT_LOG_ENTRY();

    // Set the program type as the provider module id.
    _ebpf_sock_ops_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_SOCK_OPS;
    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_sock_ops_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    _net_ebpf_sock_ops_hook_provider_data.supported_program_type = EBPF_PROGRAM_TYPE_SOCK_OPS;
    _net_ebpf_sock_ops_hook_provider_data.bpf_attach_type = BPF_CGROUP_SOCK_OPS;
    _net_ebpf_sock_ops_hook_provider_data.link_type = BPF_LINK_TYPE_CGROUP;

    // Set the attach type as the provider module id.
    _ebpf_sock_ops_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS;
    // Register the provider context and pass the pointer to the WFP filter parameters
    // corresponding to this hook type as custom data.
    status = net_ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        net_ebpf_extension_sock_ops_on_client_attach,
        _net_ebpf_extension_sock_ops_on_client_detach,
        NULL,
        &_ebpf_sock_ops_hook_provider_context);

    if (status != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        net_ebpf_ext_sock_ops_unregister_providers();
    }
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_sock_ops_unregister_providers()
{
    if (_ebpf_sock_ops_hook_provider_context) {
        net_ebpf_extension_hook_provider_unregister(_ebpf_sock_ops_hook_provider_context);
        _ebpf_sock_ops_hook_provider_context = NULL;
    }
    if (_ebpf_sock_ops_program_info_provider_context) {
        net_ebpf_extension_program_info_provider_unregister(_ebpf_sock_ops_program_info_provider_context);
        _ebpf_sock_ops_program_info_provider_context = NULL;
    }
}

wfp_ale_layer_fields_t wfp_flow_established_fields[] = {
    // EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4
    {FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_COMPARTMENT_ID,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_INTERFACE},
    // EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6
    {FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_COMPARTMENT_ID,
     FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_INTERFACE}};

static void
_net_ebpf_extension_sock_ops_copy_wfp_connection_fields(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values, _Out_ bpf_sock_ops_t* sock_ops_context)
{
    uint16_t wfp_layer_id = incoming_fixed_values->layerId;
    net_ebpf_extension_hook_id_t hook_id = net_ebpf_extension_get_hook_id_from_wfp_layer_id(wfp_layer_id);
    wfp_ale_layer_fields_t* fields = &wfp_flow_established_fields[hook_id - EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4];

    FWPS_INCOMING_VALUE0* incoming_values = incoming_fixed_values->incomingValue;

    sock_ops_context->op = (incoming_values[fields->direction_field].value.uint32 == FWP_DIRECTION_OUTBOUND)
                               ? BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
                               : BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB;

    // Copy IP address fields.
    if (hook_id == EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4) {
        sock_ops_context->family = AF_INET;
        sock_ops_context->local_ip4 = htonl(incoming_values[fields->local_ip_address_field].value.uint32);
        sock_ops_context->remote_ip4 = htonl(incoming_values[fields->remote_ip_address_field].value.uint32);
    } else {
        sock_ops_context->family = AF_INET6;
        RtlCopyMemory(
            sock_ops_context->local_ip6,
            incoming_values[fields->local_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
        RtlCopyMemory(
            sock_ops_context->remote_ip6,
            incoming_values[fields->remote_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
    }
    sock_ops_context->local_port = htons(incoming_values[fields->local_port_field].value.uint16);
    sock_ops_context->remote_port = htons(incoming_values[fields->remote_port_field].value.uint16);
    sock_ops_context->protocol = incoming_values[fields->protocol_field].value.uint8;
    sock_ops_context->compartment_id = incoming_values[fields->compartment_id_field].value.uint32;
    sock_ops_context->interface_luid = *incoming_values[fields->interface_luid_field].value.uint64;
}

//
// WFP callout callback function.
//
void
net_ebpf_extension_sock_ops_flow_established_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    NTSTATUS status;
    uint32_t result;
    net_ebpf_extension_sock_ops_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_hook_client_t* attached_client = NULL;
    net_ebpf_extension_sock_ops_wfp_flow_context_t* local_flow_context = NULL;
    bpf_sock_ops_t* sock_ops_context = NULL;
    uint32_t client_compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    net_ebpf_extension_hook_id_t hook_id =
        net_ebpf_extension_get_hook_id_from_wfp_layer_id(incoming_fixed_values->layerId);
    KIRQL irql;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_sock_ops_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        goto Exit;
    }

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->base.client_context;
    if (attached_client == NULL) {
        goto Exit;
    }

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client)) {
        attached_client = NULL;
        goto Exit;
    }

    local_flow_context = (net_ebpf_extension_sock_ops_wfp_flow_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_sock_ops_wfp_flow_context_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (local_flow_context == NULL) {
        result = EBPF_NO_MEMORY;
        NET_EBPF_EXT_LOG_FUNCTION_ERROR(result);
        goto Exit;
    }
    memset(local_flow_context, 0, sizeof(net_ebpf_extension_sock_ops_wfp_flow_context_t));

    // Associate the filter context with the filter context.
    REFERENCE_FILTER_CONTEXT(&filter_context->base);
    local_flow_context->filter_context = filter_context;

    sock_ops_context = &local_flow_context->context;
    _net_ebpf_extension_sock_ops_copy_wfp_connection_fields(incoming_fixed_values, sock_ops_context);

    client_compartment_id = filter_context->compartment_id;
    ASSERT(
        (client_compartment_id == UNSPECIFIED_COMPARTMENT_ID) ||
        (client_compartment_id == sock_ops_context->compartment_id));
    if (client_compartment_id != UNSPECIFIED_COMPARTMENT_ID &&
        client_compartment_id != sock_ops_context->compartment_id) {
        // The client is not interested in this compartment Id.
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "The cgroup_sock_ops eBPF program is not interested in this compartmentId",
            sock_ops_context->compartment_id);

        goto Exit;
    }

    local_flow_context->parameters.flow_id = incoming_metadata_values->flowHandle;
    local_flow_context->parameters.layer_id = incoming_fixed_values->layerId;
    local_flow_context->parameters.callout_id = net_ebpf_extension_get_callout_id_for_hook(hook_id);

    if (net_ebpf_extension_hook_invoke_program(attached_client, sock_ops_context, &result) != EBPF_SUCCESS) {
        goto Exit;
    }

    status = FwpsFlowAssociateContext(
        local_flow_context->parameters.flow_id,
        local_flow_context->parameters.layer_id,
        local_flow_context->parameters.callout_id,
        (uint64_t)(uintptr_t)local_flow_context);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS, "FwpsFlowAssociateContext", status);
        goto Exit;
    }

    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS,
        "New flow created.",
        local_flow_context->parameters.flow_id);

    KeAcquireSpinLock(&filter_context->lock, &irql);
    InsertTailList(&filter_context->flow_context_list.list_head, &local_flow_context->link);
    filter_context->flow_context_list.count++;
    KeReleaseSpinLock(&filter_context->lock, irql);
    local_flow_context = NULL;

    classify_output->actionType = (result == 0) ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    if (classify_output->actionType == FWP_ACTION_BLOCK) {
        classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }

Exit:
    if (local_flow_context != NULL) {
        ExFreePool(local_flow_context);
    }
    if (attached_client != NULL) {
        net_ebpf_extension_hook_client_leave_rundown(attached_client);
    }
}

void
net_ebpf_extension_sock_ops_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context)
{
    net_ebpf_extension_sock_ops_wfp_flow_context_t* local_flow_context =
        (net_ebpf_extension_sock_ops_wfp_flow_context_t*)(uintptr_t)flow_context;
    net_ebpf_extension_sock_ops_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_hook_client_t* attached_client = NULL;
    bpf_sock_ops_t* sock_ops_context = NULL;
    uint32_t result;
    KIRQL irql = 0;

    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);

    ASSERT(local_flow_context != NULL);
    if (local_flow_context == NULL) {
        goto Exit;
    }

    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS,
        "Flow deleted.",
        local_flow_context->parameters.flow_id);

    filter_context = local_flow_context->filter_context;
    if (filter_context == NULL) {
        goto Exit;
    }

    if (local_flow_context->client_detached) {
        // Since the hook client is detached, exit the function.
        goto Exit;
    }

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->base.client_context;
    if (attached_client == NULL) {
        // This means that the eBPF program is detached and there is nothing to notify.
        goto Exit;
    }

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client)) {
        attached_client = NULL;
        goto Exit;
    }

    KeAcquireSpinLock(&filter_context->lock, &irql);
    RemoveEntryList(&local_flow_context->link);
    filter_context->flow_context_list.count--;
    KeReleaseSpinLock(&filter_context->lock, irql);

    // Invoke eBPF program with connection deleted socket event.
    sock_ops_context = &local_flow_context->context;
    sock_ops_context->op = BPF_SOCK_OPS_CONNECTION_DELETED_CB;
    if (net_ebpf_extension_hook_invoke_program(attached_client, sock_ops_context, &result) != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    if (filter_context) {
        DEREFERENCE_FILTER_CONTEXT(&filter_context->base);
    }
    if (local_flow_context != NULL) {
        ExFreePool(local_flow_context);
    }
    if (attached_client != NULL) {
        net_ebpf_extension_hook_client_leave_rundown(attached_client);
    }
}

static ebpf_result_t
_ebpf_sock_ops_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    ebpf_result_t result;
    bpf_sock_ops_t* sock_ops_context = NULL;

    *context = NULL;

    // This provider doesn't support data.
    if (data_in != NULL || data_size_in != 0) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "Data is not supported");
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // This provider requires context.
    if (context_in == NULL || context_size_in < sizeof(bpf_sock_ops_t)) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    sock_ops_context =
        (bpf_sock_ops_t*)ExAllocatePoolUninitialized(NonPagedPool, sizeof(bpf_sock_ops_t), NET_EBPF_EXTENSION_POOL_TAG);

    if (sock_ops_context == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    memcpy(sock_ops_context, context_in, sizeof(bpf_sock_ops_t));

    *context = sock_ops_context;
    sock_ops_context = NULL;
    result = EBPF_SUCCESS;

Done:
    if (sock_ops_context != NULL) {
        ExFreePool(sock_ops_context);
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_sock_ops_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    UNREFERENCED_PARAMETER(data_out);
    if (context == NULL) {
        return;
    }

    // This provider doesn't support data.

    *data_size_out = 0;

    if (context_out != NULL && *context_size_out >= sizeof(bpf_sock_ops_t)) {
        memcpy(context_out, context, sizeof(bpf_sock_ops_t));
        *context_size_out = sizeof(bpf_sock_ops_t);
    } else {
        *context_size_out = 0;
    }

    ExFreePool(context);
    NET_EBPF_EXT_LOG_FUNCTION_SUCCESS();
}