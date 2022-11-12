// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file This file implements the hook for the CGROUP_SOCK_ADDR program type and associated attach types, on eBPF for
 * Windows.
 *
 */

#include "net_ebpf_ext.h"

#include "ebpf_store_helper.h"
#include "net_ebpf_ext_sock_addr.h"

#define TARGET_PROCESS_ID 1234
#define EXPIRY_TIME 60000 // 60 seconds in ms.

#define NET_EBPF_EXT_OPTION_LOOPBACK (1 << 0)
#define NET_EBPF_EXT_OPTION_REDIRECT (1 << 1)
// #define NET_EBPF_EXT_OPTION_AUTH_CALLED (1 << 2)

typedef struct _net_ebpf_extension_connection_context
{
    LIST_ENTRY list_entry;
    bpf_sock_addr_t destination;
    uint64_t transport_endpoint_handle;
    uint8_t flags;
    uint8_t verdict;
    uint16_t protocol;
    uint64_t timestamp;
} net_ebpf_extension_connection_context_t;

typedef struct _net_ebpf_extension_redirect_handle_entry
{
    LIST_ENTRY list_entry;
    uint64_t filter_id;
    HANDLE redirect_handle;
} net_ebpf_extension_redirect_handle_entry_t;

typedef struct _net_ebpf_ext_sock_addr_statistics
{
    volatile long permit_connection_count;
    volatile long redirect_connection_count;
    volatile long block_connection_count;
} net_ebpf_ext_sock_addr_statistics_t;

static net_ebpf_ext_sock_addr_statistics_t _net_ebpf_ext_statistics;

static EX_SPIN_LOCK _net_ebpf_ext_redirect_handle_lock;
_Guarded_by_(_net_ebpf_ext_redirect_handle_lock) static LIST_ENTRY _net_ebpf_ext_redirect_handle_list;
_Guarded_by_(_net_ebpf_ext_redirect_handle_lock) static LIST_ENTRY _net_ebpf_ext_connect_context_list;
static uint32_t _net_ebpf_ext_connect_context_count = 0;

//
// WFP filter related types & globals for SOCK_ADDR hook.
//

const ebpf_attach_type_t* _net_ebpf_extension_sock_addr_attach_types[] = {
    &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
    &EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT,
    &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT,
    &EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT};

const uint32_t _net_ebpf_extension_sock_addr_bpf_attach_types[] = {
    BPF_CGROUP_INET4_CONNECT, BPF_CGROUP_INET4_RECV_ACCEPT, BPF_CGROUP_INET6_CONNECT, BPF_CGROUP_INET6_RECV_ACCEPT};

#define NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT EBPF_COUNT_OF(_net_ebpf_extension_sock_addr_attach_types)

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet4_connect_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
     NULL,
     &EBPF_HOOK_ALE_AUTH_CONNECT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},

    {&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
     NULL,
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},

    {&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V4_SUBLAYER,
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet6_connect_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
     NULL,
     &EBPF_HOOK_ALE_AUTH_CONNECT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},

    {&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V6_SUBLAYER,
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet4_recv_accept_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
     NULL,
     &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet6_recv_accept_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
     NULL,
     &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

const net_ebpf_extension_wfp_filter_parameters_array_t _net_ebpf_extension_sock_addr_wfp_filter_parameters[] = {
    {&EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
     EBPF_COUNT_OF(_cgroup_inet4_connect_filter_parameters),
     &_cgroup_inet4_connect_filter_parameters[0]},
    {&EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT,
     EBPF_COUNT_OF(_cgroup_inet4_recv_accept_filter_parameters),
     &_cgroup_inet4_recv_accept_filter_parameters[0]},
    {&EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT,
     EBPF_COUNT_OF(_cgroup_inet6_connect_filter_parameters),
     &_cgroup_inet6_connect_filter_parameters[0]},
    {&EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT,
     EBPF_COUNT_OF(_cgroup_inet6_recv_accept_filter_parameters),
     &_cgroup_inet6_recv_accept_filter_parameters[0]},
};

typedef struct _net_ebpf_extension_sock_addr_wfp_filter_context
{
    net_ebpf_extension_wfp_filter_context_t base;
    uint32_t compartment_id;
    bool v4_attach_type;
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

ebpf_attach_provider_data_t _net_ebpf_sock_addr_hook_provider_data[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};
ebpf_extension_data_t _net_ebpf_extension_sock_addr_hook_provider_data[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};
NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_addr_hook_provider_moduleid[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};

static net_ebpf_extension_hook_provider_t*
    _ebpf_sock_addr_hook_provider_context[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};

//
// NMR Registration Helper Routines.
//

static ebpf_result_t
_net_ebpf_extension_sock_addr_on_client_attach(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    const ebpf_extension_data_t* client_data = net_ebpf_extension_hook_client_get_client_data(attaching_client);
    uint32_t compartment_id;
    uint32_t wild_card_compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    net_ebpf_extension_wfp_filter_parameters_array_t* filter_parameters = NULL;
    FWPM_FILTER_CONDITION condition = {0};
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

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
        // If the client did not specify any attach parameters, we treat that as a wildcard compartment id.
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

    result = net_ebpf_extension_wfp_filter_context_create(
        sizeof(net_ebpf_extension_sock_addr_wfp_filter_context_t),
        attaching_client,
        (net_ebpf_extension_wfp_filter_context_t**)&filter_context);
    if (result != EBPF_SUCCESS)
        goto Exit;
    filter_context->compartment_id = compartment_id;

    // Get the WFP filter parameters for this hook type.
    filter_parameters =
        (net_ebpf_extension_wfp_filter_parameters_array_t*)net_ebpf_extension_hook_provider_get_custom_data(
            provider_context);
    ASSERT(filter_parameters != NULL);
    filter_context->base.filter_ids_count = filter_parameters->count;

    // Special case of connect_redirect. If the attach type is v4, set is_v4 in the filter context.
    if (memcmp(filter_parameters->attach_type, &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, sizeof(GUID)) == 0) {
        filter_context->v4_attach_type = true;
    }

    // Add a single WFP filter at the WFP layer corresponding to the hook type, and set the hook NPI client as the
    // filter's raw context.
    result = net_ebpf_extension_add_wfp_filters(
        filter_parameters->count, // filter_count
        filter_parameters->filter_parameters,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? 0 : 1,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? NULL : &condition,
        (net_ebpf_extension_wfp_filter_context_t*)filter_context,
        &filter_context->base.filter_ids);
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

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static void
_net_ebpf_extension_sock_addr_on_client_detach(_In_ const net_ebpf_extension_hook_client_t* detaching_client)
{
    NET_EBPF_EXT_LOG_ENTRY();
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context =
        (net_ebpf_extension_sock_addr_wfp_filter_context_t*)net_ebpf_extension_hook_client_get_provider_data(
            detaching_client);
    ASSERT(filter_context != NULL);
    net_ebpf_extension_delete_wfp_filters(filter_context->base.filter_ids_count, filter_context->base.filter_ids);
    net_ebpf_extension_wfp_filter_context_cleanup((net_ebpf_extension_wfp_filter_context_t*)filter_context);
}

static NTSTATUS
_net_ebpf_sock_addr_update_store_entries()
{
    NTSTATUS status;

    // Update section information.
    uint32_t section_info_count = sizeof(_ebpf_sock_addr_section_info) / sizeof(ebpf_program_section_info_t);
    status = ebpf_store_update_section_information(&_ebpf_sock_addr_section_info[0], section_info_count);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Update program information.
    _ebpf_sock_addr_program_info.program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
    status = ebpf_store_update_program_information(&_ebpf_sock_addr_program_info, 1);

    return status;
}

static void
_net_ebpf_sock_addr_initialize_globals()
{
    InitializeListHead(&_net_ebpf_ext_redirect_handle_list);
    InitializeListHead(&_net_ebpf_ext_connect_context_list);
}

static NTSTATUS
_net_ebpf_ext_sock_addr_update_redirect_handle(uint64_t filter_id, HANDLE redirect_handle)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL old_irql;

    net_ebpf_extension_redirect_handle_entry_t* entry =
        (net_ebpf_extension_redirect_handle_entry_t*)ExAllocatePoolUninitialized(
            NonPagedPoolNx, sizeof(net_ebpf_extension_redirect_handle_entry_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (entry == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    memset(entry, 0, sizeof(net_ebpf_extension_redirect_handle_entry_t));
    entry->filter_id = filter_id;
    entry->redirect_handle = redirect_handle;

    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock);
    InsertTailList(&_net_ebpf_ext_redirect_handle_list, &entry->list_entry);
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock, old_irql);

Exit:
    return status;
}

static void
_net_ebpf_ext_sock_addr_delete_redirect_handle(uint64_t filter_id)
{
    KIRQL old_irql;

    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock);

    LIST_ENTRY* list_entry = _net_ebpf_ext_redirect_handle_list.Flink;
    while (list_entry != &_net_ebpf_ext_redirect_handle_list) {
        net_ebpf_extension_redirect_handle_entry_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_redirect_handle_entry_t, list_entry);
        if (entry->filter_id == filter_id) {
            RemoveEntryList(list_entry);
            ExFreePool(entry);
            break;
        }
        list_entry = list_entry->Flink;
    }
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock, old_irql);
}

static NTSTATUS
_net_ebpf_ext_sock_addr_get_redirect_handle(uint64_t filter_id, _Out_ HANDLE* redirect_handle)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL old_irql;

    old_irql = ExAcquireSpinLockShared(&_net_ebpf_ext_redirect_handle_lock);

    LIST_ENTRY* list_entry = _net_ebpf_ext_redirect_handle_list.Flink;
    while (list_entry != &_net_ebpf_ext_redirect_handle_list) {
        net_ebpf_extension_redirect_handle_entry_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_redirect_handle_entry_t, list_entry);
        if (entry->filter_id == filter_id) {
            *redirect_handle = entry->redirect_handle;
            status = STATUS_SUCCESS;
            break;
        }
        list_entry = list_entry->Flink;
    }

    ExReleaseSpinLockShared(&_net_ebpf_ext_redirect_handle_lock, old_irql);

    return status;
}

static void
_net_ebpf_ext_initialize_connection_context(
    bool redirected,
    bool loopback,
    uint32_t verdict,
    uint64_t transport_endpoint_handle,
    uint32_t protocol,
    _Out_ net_ebpf_extension_connection_context_t* connection_context)
{
    connection_context->protocol = (uint16_t)protocol;
    if (redirected) {
        connection_context->flags |= NET_EBPF_EXT_OPTION_REDIRECT;
    }
    if (loopback) {
        connection_context->flags |= NET_EBPF_EXT_OPTION_LOOPBACK;
    }
    connection_context->verdict = (uint8_t)verdict;
    connection_context->transport_endpoint_handle = transport_endpoint_handle;
    connection_context->timestamp = KeQueryInterruptTime() / 10000; // in ms.
}

static bool
_net_ebpf_ext_is_loopback_address(_In_ const bpf_sock_addr_t* address)
{
    SOCKADDR_STORAGE socket_address = {0};
    socket_address.ss_family = (ADDRESS_FAMILY)address->family;
    if (socket_address.ss_family == AF_INET) {
        SOCKADDR_IN* v4_address = (SOCKADDR_IN*)&socket_address;
        v4_address->sin_addr.S_un.S_addr = address->user_ip4;
    } else {
        SOCKADDR_IN6* v6_address = (SOCKADDR_IN6*)&socket_address;
        RtlCopyMemory(v6_address->sin6_addr.u.Byte, address->user_ip6, 16);
    }

    return INETADDR_ISLOOPBACK((SOCKADDR*)&socket_address);
}

/**
 * @brief Compare the destination address in the two provided bpf_sock_addr_t structs.
 *
 * @param[in] addr1 Pointer to first sock_addr struct to compare.
 * @param[in] addr2 Pointer to second sock_addr struct to compare.

 * @return true, if the addresses are same, false otherwise.
 */
static inline bool
_net_ebpf_ext_compare_destination_address(_In_ const bpf_sock_addr_t* addr1, _In_ const bpf_sock_addr_t* addr2)
{
    ASSERT(addr1->family == addr2->family);
    if (addr1->family != addr2->family) {
        return false;
    }

    if (addr1->family == AF_INET) {
        return addr1->user_ip4 == addr2->user_ip4;
    } else {
        return (memcmp(&addr1->user_ip6[0], &addr2->user_ip6[0], 16) == 0);
    }
}

static NTSTATUS
_net_ebpf_ext_get_connection_context(
    uint64_t transport_endpoint_handle,
    _In_ const bpf_sock_addr_t* sock_addr_ctx,
    _Out_ net_ebpf_extension_connection_context_t** connection_context)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL old_irql;

    *connection_context = NULL;
    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock);

    LIST_ENTRY* list_entry = _net_ebpf_ext_connect_context_list.Flink;
    while (list_entry != &_net_ebpf_ext_connect_context_list) {
        net_ebpf_extension_connection_context_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_connection_context_t, list_entry);
        if (entry->transport_endpoint_handle == transport_endpoint_handle) {
            // Check if the destination address and port match.
            if (_net_ebpf_ext_compare_destination_address(&entry->destination, sock_addr_ctx) &&
                entry->destination.user_port == sock_addr_ctx->user_port) {
                // Found matching entry. Update timestamp and move to front of the queue.
                entry->timestamp = KeQueryInterruptTime() / 10000;
                RemoveEntryList(&entry->list_entry);
                InsertHeadList(&_net_ebpf_ext_connect_context_list, &entry->list_entry);

                *connection_context = entry;
                status = STATUS_SUCCESS;
                break;
            }
        }
        list_entry = list_entry->Flink;
    }

    ExReleaseSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock, old_irql);

    return status;
}

static void
_net_ebpf_ext_delete_connection_context(_In_ _Post_invalid_ net_ebpf_extension_connection_context_t* context)
{
    KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock);

    RemoveEntryList(&context->list_entry);
    ExFreePool(context);
    _net_ebpf_ext_connect_context_count--;

    ExReleaseSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock, old_irql);
}

static void
_net_ebpf_ext_purge_lru_contexts_under_lock(bool delete_all)
{
    uint64_t expiry_time = KeQueryInterruptTime() / 10000 - EXPIRY_TIME;

    LIST_ENTRY* list_entry = _net_ebpf_ext_connect_context_list.Blink;
    while (list_entry != &_net_ebpf_ext_connect_context_list) {
        net_ebpf_extension_connection_context_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_connection_context_t, list_entry);
        if (!delete_all && entry->timestamp > expiry_time) {
            break;
        }
        list_entry = list_entry->Blink;
        RemoveEntryList(&entry->list_entry);

        _net_ebpf_ext_connect_context_count--;

        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "_net_ebpf_ext_purge_lru_contexts_under_lock: Delete",
            entry->transport_endpoint_handle);

        ExFreePool(entry);
    }

    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_INFO,
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
        "_net_ebpf_ext_purge_lru_contexts_under_lock",
        _net_ebpf_ext_connect_context_count);
}

static void
_net_ebpf_ext_purge_lru_contexts(bool delete_all)
{
    KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock);
    _net_ebpf_ext_purge_lru_contexts_under_lock(delete_all);
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock, old_irql);
}

static void
_net_ebpf_ext_insert_connection_context_to_list(_In_ net_ebpf_extension_connection_context_t* connection_context)
{
    KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock);

    // Insert the most recent entry at the head.
    InsertHeadList(&_net_ebpf_ext_connect_context_list, &connection_context->list_entry);
    _net_ebpf_ext_connect_context_count++;

    // Purge stale entries from the list.
    _net_ebpf_ext_purge_lru_contexts_under_lock(false);

    ExReleaseSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock, old_irql);
}

NTSTATUS
net_ebpf_ext_sock_addr_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    status = _net_ebpf_sock_addr_update_store_entries();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    _net_ebpf_sock_addr_initialize_globals();

    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_sock_addr_program_info_provider_moduleid, &_ebpf_sock_addr_program_info_provider_data};

    NET_EBPF_EXT_LOG_ENTRY();

    _ebpf_sock_addr_program_info.program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
    // Set the program type as the provider module id.
    _ebpf_sock_addr_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_sock_addr_program_info_provider_context);
    if (status != STATUS_SUCCESS)
        goto Exit;

    for (int i = 0; i < NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT; i++) {
        const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
            &_ebpf_sock_addr_hook_provider_moduleid[i], &_net_ebpf_extension_sock_addr_hook_provider_data[i]};

        _net_ebpf_sock_addr_hook_provider_data[i].supported_program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
        _net_ebpf_sock_addr_hook_provider_data[i].bpf_attach_type =
            (bpf_attach_type_t)_net_ebpf_extension_sock_addr_bpf_attach_types[i];
        _net_ebpf_sock_addr_hook_provider_data[i].link_type = BPF_LINK_TYPE_CGROUP;
        _net_ebpf_extension_sock_addr_hook_provider_data[i].version = EBPF_ATTACH_PROVIDER_DATA_VERSION;
        _net_ebpf_extension_sock_addr_hook_provider_data[i].data = &_net_ebpf_sock_addr_hook_provider_data[i];
        _net_ebpf_extension_sock_addr_hook_provider_data[i].size = sizeof(ebpf_attach_provider_data_t);

        // Set the attach type as the provider module id.
        _ebpf_sock_addr_hook_provider_moduleid[i].Length = sizeof(NPI_MODULEID);
        _ebpf_sock_addr_hook_provider_moduleid[i].Type = MIT_GUID;
        _ebpf_sock_addr_hook_provider_moduleid[i].Guid = *_net_ebpf_extension_sock_addr_attach_types[i];
        // Register the provider context and pass the pointer to the WFP filter parameters
        // corresponding to this hook type as custom data.
        status = net_ebpf_extension_hook_provider_register(
            &hook_provider_parameters,
            _net_ebpf_extension_sock_addr_on_client_attach,
            _net_ebpf_extension_sock_addr_on_client_detach,
            &_net_ebpf_extension_sock_addr_wfp_filter_parameters[i],
            &_ebpf_sock_addr_hook_provider_context[i]);
    }

    if (status != EBPF_SUCCESS)
        goto Exit;

Exit:
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_sock_addr_unregister_providers()
{
    for (int i = 0; i < NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT; i++)
        net_ebpf_extension_hook_provider_unregister(_ebpf_sock_addr_hook_provider_context[i]);
    net_ebpf_extension_program_info_provider_unregister(_ebpf_sock_addr_program_info_provider_context);

    _net_ebpf_ext_purge_lru_contexts(true);
}

typedef enum _net_ebpf_extension_sock_addr_connection_direction
{
    EBPF_HOOK_SOCK_ADDR_INGRESS = 0,
    EBPF_HOOK_SOCK_ADDR_EGRESS
} net_ebpf_extension_sock_addr_connection_direction_t;

static net_ebpf_extension_sock_addr_connection_direction_t
_net_ebpf_extension_sock_addr_get_connection_direction_from_hook_id(net_ebpf_extension_hook_id_t hook_id)
{
    return ((hook_id == EBPF_HOOK_ALE_AUTH_CONNECT_V4) || (hook_id == EBPF_HOOK_ALE_AUTH_CONNECT_V6) ||
            (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V4) || (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V6))
               ? EBPF_HOOK_SOCK_ADDR_EGRESS
               : EBPF_HOOK_SOCK_ADDR_INGRESS;
}

wfp_ale_layer_fields_t wfp_connection_fields[] = {
    // EBPF_HOOK_ALE_AUTH_CONNECT_V4
    {FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_INTERFACE},

    // EBPF_HOOK_ALE_AUTH_CONNECT_V6
    {FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_INTERFACE},

    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V4
    {
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL,
        0, // No direction field in this layer.
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_COMPARTMENT_ID,
        0 // No interface luid in this layer.
    },

    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V6
    {
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_PORT,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL,
        0, // No direction field in this layer.
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_COMPARTMENT_ID,
        0 // No interface luid in this layer.
    },

    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4
    {FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_INTERFACE},

    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6
    {FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_INTERFACE}};

static void
_net_ebpf_extension_sock_addr_copy_wfp_connection_fields(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values, _Out_ bpf_sock_addr_t* sock_addr_ctx)
{
    net_ebpf_extension_hook_id_t hook_id =
        net_ebpf_extension_get_hook_id_from_wfp_layer_id(incoming_fixed_values->layerId);
    net_ebpf_extension_sock_addr_connection_direction_t direction =
        _net_ebpf_extension_sock_addr_get_connection_direction_from_hook_id(hook_id);
    wfp_ale_layer_fields_t* fields = &wfp_connection_fields[hook_id - EBPF_HOOK_ALE_AUTH_CONNECT_V4];

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
    if ((hook_id == EBPF_HOOK_ALE_AUTH_CONNECT_V4) || (hook_id == EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4) ||
        (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V4)) {
        sock_addr_ctx->family = AF_INET;
        sock_addr_ctx->msg_src_ip4 = htonl(incoming_values[source_ip_address_field].value.uint32);
        sock_addr_ctx->user_ip4 = htonl(incoming_values[destination_ip_address_field].value.uint32);
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
    sock_addr_ctx->msg_src_port = htons(incoming_values[source_port_field].value.uint16);
    sock_addr_ctx->user_port = htons(incoming_values[destination_port_field].value.uint16);
    sock_addr_ctx->protocol = incoming_values[fields->protocol_field].value.uint8;
    sock_addr_ctx->compartment_id = incoming_values[fields->compartment_id_field].value.uint32;

    if (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V4 || hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V6) {
        sock_addr_ctx->interface_luid = 0;
    } else {
        sock_addr_ctx->interface_luid = *incoming_values[fields->interface_luid_field].value.uint64;
    }
}

NTSTATUS
net_ebpf_ext_connect_redirect_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ FWPS_FILTER* filter)
{
    NET_EBPF_EXT_LOG_ENTRY();
    NTSTATUS status = STATUS_SUCCESS;

    if (callout_notification_type == FWPS_CALLOUT_NOTIFY_ADD_FILTER) {
        HANDLE redirect_handle;
        status = FwpsRedirectHandleCreate(&EBPF_HOOK_ALE_CONNECT_REDIRECT_PROVIDER, 0, &redirect_handle);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }

        status = _net_ebpf_ext_sock_addr_update_redirect_handle(filter->filterId, redirect_handle);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
    } else if (callout_notification_type == FWPS_CALLOUT_NOTIFY_DELETE_FILTER) {
        _net_ebpf_ext_sock_addr_delete_redirect_handle(filter->filterId);
    }

    net_ebpf_ext_filter_change_notify(callout_notification_type, filter_key, filter);

Exit:
    return status;
}

//
// WFP callout callback functions.
//

void
net_ebpf_extension_sock_addr_authorize_recv_accept_classify(
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
    bpf_sock_addr_t sock_addr_ctx = {0};
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;

    UNREFERENCED_PARAMETER(incoming_metadata_values);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL)
        goto Exit;

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->base.client_context;
    if (attached_client == NULL)
        goto Exit;

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client)) {
        attached_client = NULL;
        goto Exit;
    }

    _net_ebpf_extension_sock_addr_copy_wfp_connection_fields(incoming_fixed_values, &sock_addr_ctx);

    compartment_id = filter_context->compartment_id;
    ASSERT((compartment_id == UNSPECIFIED_COMPARTMENT_ID) || (compartment_id == sock_addr_ctx.compartment_id));
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID && compartment_id != sock_addr_ctx.compartment_id) {
        // The client is not interested in this compartment Id.
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "The cgroup_sock_addr eBPF program is not interested in this compartmentId",
            sock_addr_ctx.compartment_id);

        goto Exit;
    }

    if (net_ebpf_extension_hook_invoke_program(attached_client, &sock_addr_ctx, &result) != EBPF_SUCCESS)
        goto Exit;

    classify_output->actionType = (result == BPF_SOCK_ADDR_VERDICT_PROCEED) ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    if (classify_output->actionType == FWP_ACTION_BLOCK)
        classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;

    NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
        "net_ebpf_extension_sock_addr_authorize_recv_accept_classify",
        incoming_metadata_values->transportEndpointHandle,
        sock_addr_ctx.protocol,
        result);

Exit:
    if (attached_client)
        net_ebpf_extension_hook_client_leave_rundown(attached_client);
}

/*
 * Default action is BLOCK. If this callout is being invoked, it means at least one
 * eBPF program is attached. Hence no connection should be allowed unless allowed by
 * the eBPF program.
 */
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
    uint32_t result = BPF_SOCK_ADDR_VERDICT_REJECT;
    NTSTATUS status;
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;
    bpf_sock_addr_t sock_addr_ctx = {0};
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    FWP_ACTION_TYPE action = FWP_ACTION_BLOCK;
    net_ebpf_extension_connection_context_t* connection_context = NULL;

    UNREFERENCED_PARAMETER(incoming_metadata_values);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL)
        goto Exit;

    _net_ebpf_extension_sock_addr_copy_wfp_connection_fields(incoming_fixed_values, &sock_addr_ctx);

    compartment_id = filter_context->compartment_id;
    ASSERT((compartment_id == UNSPECIFIED_COMPARTMENT_ID) || (compartment_id == sock_addr_ctx.compartment_id));
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID && compartment_id != sock_addr_ctx.compartment_id) {
        // The client is not interested in this compartment Id.
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "The cgroup_sock_addr eBPF program is not interested in this compartmentId",
            sock_addr_ctx.compartment_id);

        action = FWP_ACTION_PERMIT;
        goto Exit;
    }

    // Get the connection context for this connection.
    status = _net_ebpf_ext_get_connection_context(
        incoming_metadata_values->transportEndpointHandle, &sock_addr_ctx, &connection_context);
    if (!NT_SUCCESS(status)) {
        // We did not find any connection context for this AUTH request. Block.
        action = FWP_ACTION_BLOCK;

        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "ANUSA: net_ebpf_extension_sock_addr_authorize_connection_classify: did not find matching context",
            incoming_metadata_values->transportEndpointHandle,
            sock_addr_ctx.family,
            sock_addr_ctx.protocol);
        goto Exit;
    }
    result = connection_context->verdict;

    // if (!(connection_context->flags & NET_EBPF_EXT_OPTION_AUTH_CALLED)) {
    //     // If this is the first time AUTH has been called for this connection,
    //     // set NET_EBPF_EXT_OPTION_AUTH_CALLED flag.
    //     connection_context->flags |= NET_EBPF_EXT_OPTION_AUTH_CALLED;
    // } else {
    //     // If this is the second AUTH call, we are now done with this connection
    //     // context and it is safe to free this context.
    //     _net_ebpf_ext_delete_connection_context(connection_context);
    //     connection_context = NULL;
    // }
    _net_ebpf_ext_delete_connection_context(connection_context);
    connection_context = NULL;

    action = (result == BPF_SOCK_ADDR_VERDICT_PROCEED) ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;

Exit:
    classify_output->actionType = action;
    // Clear FWPS_RIGHT_ACTION_WRITE only when it is a hard block.
    if (action == FWP_ACTION_BLOCK) {
        classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }

    NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
        "net_ebpf_extension_sock_addr_authorize_connection_classify",
        incoming_metadata_values->transportEndpointHandle,
        sock_addr_ctx.protocol,
        action);

    return;
}

/*
 * Default action is BLOCK. If this callout is being invoked, it means at least one
 * eBPF program is attached. Hence no connection should be allowed unless allowed by
 * the eBPF program.
 *
 * If the eBPF program verdict is BLOCK, no context is created and AUTH classify will
 * block the connection by default.
 */
void
net_ebpf_extension_sock_addr_redirect_connection_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    uint32_t verdict;
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_hook_client_t* attached_client = NULL;
    bpf_sock_addr_t* sock_addr_ctx = NULL;
    bpf_sock_addr_t* sock_addr_ctx_original = NULL;
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    FWPS_CONNECTION_REDIRECT_STATE redirect_state;
    HANDLE redirect_handle;
    uint64_t classify_handle = 0;
    FWPS_CONNECT_REQUEST* connect_request = NULL;
    net_ebpf_extension_connection_context_t* connection_context_original = NULL;
    net_ebpf_extension_connection_context_t* connection_context_redirected = NULL;
    bool address_changed = false;
    bool redirected = false;
    FWP_ACTION_TYPE action = FWP_ACTION_BLOCK;
    bool commit_layer_data = false;
    bool classify_handle_acquired = false;
    bool v4_mapped = false;
    bool is_loopback;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((classify_output->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        // Do not modify anything and bail.
        return;
    }

    sock_addr_ctx = (bpf_sock_addr_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(bpf_sock_addr_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (sock_addr_ctx == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    sock_addr_ctx_original = (bpf_sock_addr_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(bpf_sock_addr_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (sock_addr_ctx_original == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    memset(sock_addr_ctx, 0, sizeof(bpf_sock_addr_t));
    memset(sock_addr_ctx_original, 0, sizeof(bpf_sock_addr_t));

    _net_ebpf_extension_sock_addr_copy_wfp_connection_fields(incoming_fixed_values, sock_addr_ctx);
    // Skip (and allow) any protocols other than TCP / UDP.
    /*
    if (sock_addr_ctx->protocol != IPPROTO_TCP && sock_addr_ctx->protocol != IPPROTO_UDP) {
        action = FWP_ACTION_PERMIT;
        goto Exit;
    }
    */
    *sock_addr_ctx_original = *sock_addr_ctx;

    // Check if this call is intended for us.
    filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // If the callout is invoked for v4, then it is safe to simply invoke the eBPF
    // program from the filter context.
    // If the callout is invoked for v6:
    // 1. Check if the destination is v4 mapped v6 address or pure v6 address.
    // 2. If it is v4 mapped v6 address, then we should procced only if this callout
    //    is invoked for v4 attach type.
    // 3. If it is pure v6 address, then we should procced only if this callout is
    //    invoked for v6 attach type.
    if (sock_addr_ctx->family == AF_INET6) {
        if (IN6_IS_ADDR_V4MAPPED((IN6_ADDR*)sock_addr_ctx->user_ip6)) {
            v4_mapped = true;
        }
        if (v4_mapped) {
            if (!filter_context->v4_attach_type) {
                // This callout is for v6 attach type, but address is v4 mapped v6 address.
                // Change action to permit and return.
                NET_EBPF_EXT_LOG_MESSAGE(
                    NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
                    "net_ebpf_extension_sock_addr_redirect_connection_classify: v6 attach type, v4mapped, ignoring");
                action = FWP_ACTION_PERMIT;
                goto Exit;
            }
        } else if (filter_context->v4_attach_type) {
            // This callout is for v4 attach type, but address is a pure v6 address.
            // Change action to permit and return.
            NET_EBPF_EXT_LOG_MESSAGE(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
                "net_ebpf_extension_sock_addr_redirect_connection_classify: v4 attach type, purev6, ignoring");
            action = FWP_ACTION_PERMIT;
            goto Exit;
        }
    }

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->base.client_context;
    if (attached_client == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client)) {
        attached_client = NULL;
        // Client is detaching, change action to permit.
        action = FWP_ACTION_PERMIT;
        goto Exit;
    }

    // Get the redirect handle for this filter.
    status = _net_ebpf_ext_sock_addr_get_redirect_handle(filter->filterId, &redirect_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "Failed to get redirect handle",
            filter->filterId,
            (uint64_t)sock_addr_ctx->compartment_id);
        goto Exit;
    }

    // Fetch redirect state.
    redirect_state = FwpsQueryConnectionRedirectState(incoming_metadata_values->redirectRecords, redirect_handle, NULL);
    if (redirect_state == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
        redirect_state == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "Connection redireced by self, ignoring",
            filter->filterId,
            (uint64_t)sock_addr_ctx->compartment_id);

        // We have already looked at this connection. Permit and exit.
        classify_output->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Acquire classify handle.
    status = FwpsAcquireClassifyHandle((void*)classify_context, 0, &classify_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "FwpsAcquireClassifyHandle",
            status,
            filter->filterId,
            (uint64_t)sock_addr_ctx->compartment_id);

        goto Exit;
    }
    classify_handle_acquired = true;

    if (v4_mapped) {
        sock_addr_ctx->family = AF_INET;
        const uint8_t* v4_ip = IN6_GET_ADDR_V4MAPPED((IN6_ADDR*)&sock_addr_ctx->user_ip6);
        uint32_t local_v4_ip = *((uint32_t*)v4_ip);
        memset(sock_addr_ctx->user_ip6, 0, 16);
        sock_addr_ctx->user_ip4 = local_v4_ip;
    }

    compartment_id = filter_context->compartment_id;
    ASSERT((compartment_id == UNSPECIFIED_COMPARTMENT_ID) || (compartment_id == sock_addr_ctx->compartment_id));
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID && compartment_id != sock_addr_ctx->compartment_id) {
        // The client is not interested in this compartment Id. Change action to PERMIT.
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "The cgroup_sock_addr eBPF program is not interested in this compartmentId",
            sock_addr_ctx->compartment_id);

        action = FWP_ACTION_PERMIT;
        goto Exit;
    }

    connection_context_original = (net_ebpf_extension_connection_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_connection_context_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (connection_context_original == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    memset(connection_context_original, 0, sizeof(net_ebpf_extension_connection_context_t));

    connection_context_redirected = (net_ebpf_extension_connection_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_connection_context_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (connection_context_redirected == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    memset(connection_context_redirected, 0, sizeof(net_ebpf_extension_connection_context_t));

    // Initialize connection_context_original with the original address. In case of v4 mapped socket
    // though, AUTH callout does not contain the the destination IP filled for the original destination.
    // For v4 mapped case, only fill the AF and destination port.
    if (!v4_mapped) {
        RtlCopyMemory(&connection_context_original->destination, sock_addr_ctx, sizeof(bpf_sock_addr_t));
    } else {
        connection_context_original->destination.family = sock_addr_ctx->family;
        connection_context_original->destination.user_port = sock_addr_ctx->user_port;
    }

    if (net_ebpf_extension_hook_invoke_program(attached_client, sock_addr_ctx, &verdict) != EBPF_SUCCESS) {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    // Initialize connection_context_redirected destination with the redirected address.
    RtlCopyMemory(&connection_context_redirected->destination, sock_addr_ctx, sizeof(bpf_sock_addr_t));

    is_loopback = _net_ebpf_ext_is_loopback_address(sock_addr_ctx);

    if (v4_mapped) {
        sock_addr_ctx->family = AF_INET6;
        IN_ADDR v4_address = *((IN_ADDR*)&sock_addr_ctx->user_ip4);
        IN6_SET_ADDR_V4MAPPED((IN6_ADDR*)&sock_addr_ctx->user_ip6, (IN_ADDR*)&v4_address);
    }

    // Connection context will be created only when the action is ALLOW.
    if (verdict == BPF_SOCK_ADDR_VERDICT_PROCEED) {
        // Check if destination IP and/or port have been modified.
        address_changed = !_net_ebpf_ext_compare_destination_address(sock_addr_ctx, sock_addr_ctx_original);
        if (sock_addr_ctx->user_port != sock_addr_ctx_original->user_port || address_changed) {
            redirected = true;

            status = FwpsAcquireWritableLayerDataPointer(
                classify_handle, filter->filterId, 0, (PVOID*)&connect_request, classify_output);
            if (!NT_SUCCESS(status)) {
                NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(
                    NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
                    "FwpsAcquireWritableLayerDataPointer",
                    status,
                    filter->filterId,
                    (uint64_t)sock_addr_ctx->compartment_id);

                goto Exit;
            }
            commit_layer_data = true;

            InterlockedIncrement(&_net_ebpf_ext_statistics.redirect_connection_count);

            if (sock_addr_ctx->user_port != sock_addr_ctx_original->user_port) {
                INETADDR_SET_PORT((PSOCKADDR)&connect_request->remoteAddressAndPort, ntohs(sock_addr_ctx->user_port));
            }
            if (address_changed) {
                uint8_t* address;
                if (sock_addr_ctx->family == AF_INET) {
                    address = (uint8_t*)&sock_addr_ctx->user_ip4;
                } else {
                    address = (uint8_t*)&(sock_addr_ctx->user_ip6[0]);
                }
                INETADDR_SET_ADDRESS((PSOCKADDR)&connect_request->remoteAddressAndPort, address);
            }

            // Target process id and local redirect handle needs to be set in two cases:
            // 1. The redirected address is loopback.
            // 2. The redirected address is a local non-loopback address.
            // To simplify the design, always set these values.
            connect_request->localRedirectTargetPID = TARGET_PROCESS_ID;
            connect_request->localRedirectHandle = redirect_handle;
        } else {
            InterlockedIncrement(&_net_ebpf_ext_statistics.permit_connection_count);
        }

        _net_ebpf_ext_initialize_connection_context(
            redirected,
            is_loopback,
            verdict,
            incoming_metadata_values->transportEndpointHandle,
            sock_addr_ctx->protocol,
            connection_context_redirected);

        _net_ebpf_ext_insert_connection_context_to_list(connection_context_redirected);

        if (redirected) {
            // If the connection has been redirected, then initialize connection context
            // with original destination also.
            _net_ebpf_ext_initialize_connection_context(
                redirected,
                is_loopback,
                verdict,
                incoming_metadata_values->transportEndpointHandle,
                sock_addr_ctx->protocol,
                connection_context_original);

            _net_ebpf_ext_insert_connection_context_to_list(connection_context_original);
        } else {
            ExFreePool(connection_context_original);
            connection_context_original = NULL;
        }
    } else {
        ExFreePool(connection_context_original);
        connection_context_original = NULL;
        ExFreePool(connection_context_redirected);
        connection_context_redirected = NULL;

        InterlockedIncrement(&_net_ebpf_ext_statistics.block_connection_count);
    }

    // NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(
    //     NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
    //     NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
    //     "net_ebpf_extension_sock_addr_redirect_connection_classify",
    //     incoming_metadata_values->transportEndpointHandle,
    //     sock_addr_ctx->protocol,
    //     verdict);

    NET_EBPF_EXT_LOG_SOCK_ADDR_CLASSIFY(
        NET_EBPF_EXT_TRACELOG_LEVEL_INFO,
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
        "net_ebpf_extension_sock_addr_redirect_connection_classify",
        incoming_metadata_values->transportEndpointHandle,
        sock_addr_ctx->protocol,
        redirected,
        verdict);

    action = FWP_ACTION_PERMIT;

    // TODO: What to do for redirection by multiple callouts (FWP_CONDITION_FLAG_IS_REAUTHORIZE).
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection#handling-connect-redirection-from-multiple-callouts

Exit:
    classify_output->actionType = action;
    // Clear FWPS_RIGHT_ACTION_WRITE only when it is a hard block.
    if (action == FWP_ACTION_BLOCK) {
        classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
    if (commit_layer_data) {
        FwpsApplyModifiedLayerData(classify_handle, connect_request, 0);
    }
    if (classify_handle_acquired) {
        FwpsReleaseClassifyHandle(classify_handle);
    }
    if (sock_addr_ctx) {
        ExFreePool(sock_addr_ctx);
    }
    if (sock_addr_ctx_original) {
        ExFreePool(sock_addr_ctx_original);
    }
    if (!NT_SUCCESS(status)) {
        if (connection_context_original) {
            ExFreePool(connection_context_original);
        }
        if (connection_context_redirected) {
            ExFreePool(connection_context_redirected);
        }
    }
    if (attached_client)
        net_ebpf_extension_hook_client_leave_rundown(attached_client);
}
