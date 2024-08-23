// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Details about multi-attach support implementation.
//
// Multi-attach support allows multiple eBPF programs to be attached to the same attach point (aka "hook") with the
// same attach parameters. For example, for BPF_CGROUP_INET4_CONNECT attach type, the attach parameter is the
// compartment ID. With this feature, multiple eBPF programs can be attached to the same compartment ID.
//
// "net_ebpf_extension_hook_provider_t" is the provider context for the hook NPI provider. It maintains a list of
// filter contexts. Each filter context represents a unique attach parameter. Each filter context in turn maintains
// a list of clients that were attached with that attach parameters. Each client is a unique eBPF program attached
// to the provider.
//
// Whenever a new eBPF program is attached, the provider checks if there is an existing filter context with the same
// attach parameter. If a filter context is found, the new client is added to the list of clients for that filter
// context. If no filter context is found, a new filter context is created and the new client is added to the list of
// clients for that filter context.
//
// When a client detaches, the provider removes the client from the list of clients for the filter context. If the
// filter context becomes empty, the filter context is removed from the list of filter contexts.
//
// *Synchronization*
// Access to the list of clients in the filter context and the list of filter contexts in the provider context
// needs to be synchronized. The provider maintains a DISPATCH level lock to synchronize access to these lists.
// DISPATCH level lock is chosen here as the WFP callouts can be invoked at both PASSIVE_LEVEL and DISPATCH_LEVEL.
// Attach and detach callbacks flow acquire this lock in exclusive mode, and the program invocation flow acquires
// this lock in shared mode.
// Along with the above, there is also a need to serialize attach and detach operations callbacks, as the whole
// flow of creating filter context, adding filter context to the provider list, and configuring WFP filters.
// Since WFP APIs require PASSIVE_LEVEL, the same DISPATCH_LEVEL lock cannot be used to serialize the attach and
// detach operations. To address this, a separate PASSIVE lock is maintained in the provider context to serialize
// attach and detach operations.
// As a result of this, in attach and detach operations, the flow acquires both the DISPATCH_LEVEL lock and the
// PASSIVE_LEVEL lock. In the program invocation flow, only the DISPATCH_LEVEL lock is acquired.
//
// *Wildcard vs. exact attach parameter*:
// In case there are 2 programs, one with a wildcard attach parameter and another with an exact attach parameter,
// the program with the exact attach parameter will be invoked first. WFP filters for the exact attach parameter
// will be added with higher weight than the wildcard attach parameter. This is to ensure that the program with
// more specific match will be invoked before the program with a wildcard match.

#include "ebpf_extension_uuids.h"
#include "net_ebpf_ext_hook_provider.h"

typedef struct _net_ebpf_ext_hook_client_rundown
{
    EX_RUNDOWN_REF protection;
    bool rundown_occurred;
} net_ebpf_ext_hook_rundown_t;

struct _net_ebpf_extension_hook_provider;

static volatile LONG _hook_client_counter = 0;

/**
 * @brief Data structure representing a hook NPI client (attached eBPF program). This is returned
 * as the provider binding context in the NMR client attach callback.
 */
typedef struct _net_ebpf_extension_hook_client
{
    // LIST_ENTRY link;                               ///< Link to next client (if any) in the provider context list.
    // LIST_ENTRY filter_context_link;                ///< Link to next client (if any) in the filter context list.
    HANDLE nmr_binding_handle;                     ///< NMR binding handle.
    GUID client_module_id;                         ///< NMR module Id.
    const void* client_binding_context;            ///< Client supplied context to be passed when invoking eBPF program.
    const ebpf_extension_data_t* client_data;      ///< Client supplied attach parameters.
    ebpf_program_invoke_function_t invoke_program; ///< Pointer to function to invoke eBPF program.
    // ANUSA TODO: See if we can remove provider_data.
    void* provider_data; ///< Opaque pointer to hook specific data associated with this client.
    struct _net_ebpf_extension_hook_provider* provider_context; ///< Pointer to the hook NPI provider context.
    // ANUSA TODO: Remove detach_work_item and rundown.
    PIO_WORKITEM detach_work_item;       ///< Pointer to IO work item that is invoked to detach the client.
    net_ebpf_ext_hook_rundown_t rundown; ///< Pointer to rundown object used to synchronize detach operation.
    uint64_t filter_weight;
    LONG counter;
} net_ebpf_extension_hook_client_t;

// typedef struct _net_ebpf_extension_hook_clients_list
// {
//     EX_PUSH_LOCK lock;
//     LIST_ENTRY attached_clients_list;
// } net_ebpf_extension_hook_clients_list_t;

typedef struct _net_ebpf_extension_hook_provider
{
    NPI_PROVIDER_CHARACTERISTICS characteristics; ///< NPI Provider characteristics.
    // volatile long reference_count;                ///< Reference count.
    net_ebpf_ext_hook_rundown_t rundown; ///< Rundown reference for the hook provider.
    HANDLE nmr_provider_handle;          ///< NMR binding handle.
    EX_PUSH_LOCK push_lock;              ///< Lock for serializing attach / detach calls.
    EX_SPIN_LOCK spin_lock;              ///< Lock for synchronizing access to filter_context_list.
    // net_ebpf_extension_hook_on_client_attach attach_callback; /*!< Pointer to hook specific callback to be invoked
    //                                                           when a client attaches. */
    // net_ebpf_extension_hook_on_client_detach detach_callback; /*!< Pointer to hook specific callback to be invoked
    //                                                           when a client detaches. */
    net_ebpf_extension_hook_provider_dispatch_table_t dispatch;    ///< Hook specific dispatch table.
    net_ebpf_extension_hook_attach_capability_t attach_capability; ///< Attach capability for specific hook provider.
    const void* custom_data; ///< Opaque pointer to hook specific data associated for this provider.
    _Guarded_by_(spin_lock)
        LIST_ENTRY filter_context_list; ///< Linked list of filter contexts that are attached to this provider.
} net_ebpf_extension_hook_provider_t;

/**
 * @brief Initialize the hook client rundown state.
 *
 * @param[in, out] hook_client Pointer to the attached hook NPI client.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_INSUFFICIENT_RESOURCES IO work item could not be allocated.
 */
static NTSTATUS
_ebpf_ext_attach_init_rundown(net_ebpf_extension_hook_client_t* hook_client)
{
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_ext_hook_rundown_t* rundown = &hook_client->rundown;

    NET_EBPF_EXT_LOG_ENTRY();

    //
    // Allocate work item for client detach processing.
    //
    hook_client->detach_work_item = IoAllocateWorkItem(_net_ebpf_ext_driver_device_object);
    if (hook_client->detach_work_item == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "IoAllocateWorkItem", status);
        goto Exit;
    }

    // Initialize the rundown and disable new references.
    ExInitializeRundownProtection(&rundown->protection);
    rundown->rundown_occurred = FALSE;

Exit:
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

/**
 * @brief Block execution of the thread until all invocations are completed.
 *
 * @param[in, out] rundown Rundown object to wait for.
 *
 */
static void
_ebpf_ext_attach_wait_for_rundown(_Inout_ net_ebpf_ext_hook_rundown_t* rundown)
{
    NET_EBPF_EXT_LOG_ENTRY();

    ExWaitForRundownProtectionRelease(&rundown->protection);
    rundown->rundown_occurred = TRUE;

    NET_EBPF_EXT_LOG_EXIT();
}

IO_WORKITEM_ROUTINE _net_ebpf_extension_detach_client_completion;
#if !defined(__cplusplus)
#pragma alloc_text(PAGE, _net_ebpf_extension_detach_client_completion)
#endif

/**
 * @brief IO work item routine callback that waits on client rundown to complete.
 *
 * @param[in] device_object IO Device object.
 * @param[in] context Pointer to work item context.
 *
 */
void
_net_ebpf_extension_detach_client_completion(_In_ DEVICE_OBJECT* device_object, _In_opt_ void* context)
{
    net_ebpf_extension_hook_client_t* hook_client = (net_ebpf_extension_hook_client_t*)context;
    PIO_WORKITEM work_item;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(device_object);

    NET_EBPF_EXT_LOG_ENTRY();

    ASSERT(hook_client != NULL);
    _Analysis_assume_(hook_client != NULL);

    work_item = hook_client->detach_work_item;

    // The NMR model is async, but the only Windows run-down protection API available is a blocking API, so the
    // following call will block until all using threads are complete. This should be fixed in the future.
    // Issue: https://github.com/microsoft/ebpf-for-windows/issues/1854

    // Wait for any in progress callbacks to complete.
    _ebpf_ext_attach_wait_for_rundown(&hook_client->rundown);

    IoFreeWorkItem(work_item);

    // Note: This frees the provider binding context (hook_client).
    NmrProviderDetachClientComplete(hook_client->nmr_binding_handle);

    NET_EBPF_EXT_LOG_EXIT();
}

_Must_inspect_result_ bool
net_ebpf_extension_hook_client_enter_rundown(_Inout_ net_ebpf_extension_hook_client_t* hook_client)
{
    net_ebpf_ext_hook_rundown_t* rundown = &hook_client->rundown;
    bool status = ExAcquireRundownProtection(&rundown->protection);
    return status;
}

void
net_ebpf_extension_hook_client_leave_rundown(_Inout_ net_ebpf_extension_hook_client_t* hook_client)
{
    net_ebpf_ext_hook_rundown_t* rundown = &hook_client->rundown;
    ExReleaseRundownProtection(&rundown->protection);
}

void
net_ebpf_extension_hook_provider_leave_rundown(_Inout_ net_ebpf_extension_hook_provider_t* provider_context)
{
    net_ebpf_ext_hook_rundown_t* rundown = &provider_context->rundown;
    ExReleaseRundownProtection(&rundown->protection);
}

const ebpf_extension_data_t*
net_ebpf_extension_hook_client_get_client_data(_In_ const net_ebpf_extension_hook_client_t* hook_client)
{
    return hook_client->client_data;
}

void
net_ebpf_extension_hook_client_set_provider_data(_In_ net_ebpf_extension_hook_client_t* hook_client, const void* data)
{
    hook_client->provider_data = (void*)data;
}

const void*
net_ebpf_extension_hook_client_get_provider_data(_In_ const net_ebpf_extension_hook_client_t* hook_client)
{
    return hook_client->provider_data;
}

const void*
net_ebpf_extension_hook_provider_get_custom_data(_In_ const net_ebpf_extension_hook_provider_t* provider_context)
{
    return provider_context->custom_data;
}

_Must_inspect_result_ static ebpf_result_t
_net_ebpf_extension_hook_invoke_program(
    _In_ const net_ebpf_extension_hook_client_t* client, _Inout_ void* context, _Out_ uint32_t* result)
{
    ebpf_program_invoke_function_t invoke_program = client->invoke_program;
    const void* client_binding_context = client->client_binding_context;

    ebpf_result_t invoke_result = invoke_program(client_binding_context, context, result);
    NET_EBPF_EXT_RETURN_RESULT(invoke_result);
}

_Must_inspect_result_ static ebpf_result_t
_net_ebpf_extension_hook_invoke_program2(
    _In_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _Inout_ void* context,
    _In_opt_ const net_ebpf_extension_hook_process_verdict process_callback,
    _Out_ uint32_t* result,
    _Out_ bool* continue_processing)
{
    KIRQL old_irql = PASSIVE_LEVEL;
    ebpf_result_t program_result = EBPF_OBJECT_NOT_FOUND;

    *result = 0;
    *continue_processing = true;

    // Acquire shared filter context lock.
    old_irql = ExAcquireSpinLockShared(&filter_context->lock);

    // Iterate over all the programs in the array.
    for (uint32_t i = 0; i < filter_context->client_context_count; i++) {
        const net_ebpf_extension_hook_client_t* client = filter_context->client_contexts[i];
        ASSERT(client != NULL);

        ebpf_program_invoke_function_t invoke_program = client->invoke_program;
        const void* client_binding_context = client->client_binding_context;

        program_result = invoke_program(client_binding_context, context, result);
        if (program_result != EBPF_SUCCESS) {
            // If we failed to invoke an eBPF program, stop processing and return the error code.
            goto Exit;
        }

        // Invoke callback to see if we should continue processing.
        if (process_callback != NULL) {
            if (!process_callback(*result)) {
                program_result = EBPF_SUCCESS;
                *continue_processing = false;
                goto Exit;
            }
        }
    }

Exit:
    ExReleaseSpinLockShared(&filter_context->lock, old_irql);

    return program_result;
}

static void
_net_ebpf_extension_release_rundown_for_clients(
    _Inout_ net_ebpf_extension_hook_client_t** hook_clients, uint32_t client_count)
{
    for (uint32_t i = 0; i < client_count; i++) {
        if (hook_clients[i] == NULL) {
            continue;
        }
        net_ebpf_extension_hook_client_leave_rundown(hook_clients[i]);
        hook_clients[i] = NULL;
    }
}

// 1. If we failed to invoke an eBPF program, block the connection.
// 2. If any eBPF program returned verdict as block, stop processing and return.
// _Requires_shared_lock_held_(_client_attach_lock)
ebpf_result_t
net_ebpf_extension_hook_invoke_programs(
    _Inout_ void* program_context,
    _In_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _In_opt_ const net_ebpf_extension_hook_process_verdict process_callback,
    _Out_ uint32_t* result)
{
    ebpf_result_t program_result = EBPF_SUCCESS;
    KIRQL old_irql = PASSIVE_LEVEL;
    bool lock_acquired = FALSE;
    bool wildcard_lock_acquired = FALSE;
    // bool continue_processing = true;
    net_ebpf_extension_wfp_filter_context_t* wildcard_filter_context = NULL;
    net_ebpf_extension_hook_provider_t* provider_context =
        (net_ebpf_extension_hook_provider_t*)filter_context->provider_context;
    uint32_t client_count = 0;
    net_ebpf_extension_hook_client_t* clients[NET_EBPF_EXT_MAX_CLIENTS_PER_HOOK_MULTI_ATTACH] = {0};

    *result = 0;

    // Optimization: Look for the wildcard filter context only in these cases:
    // 1. If the current filter context itself is not a wildcard filter context.
    // 2. The hook provider supports multi-attach.
    if (!filter_context->wildcard && provider_context->attach_capability == ATTACH_CAPABILITY_MULTI_ATTACH) {
        // Acquire shared spin lock for the provider context.
        old_irql = ExAcquireSpinLockShared(&provider_context->spin_lock);

        if (provider_context->filter_context_list.Blink != &provider_context->filter_context_list) {
            // Try to find the wildcard filter context, if it exists. It should be the last filter context in the list.
            wildcard_filter_context = (net_ebpf_extension_wfp_filter_context_t*)CONTAINING_RECORD(
                provider_context->filter_context_list.Blink, net_ebpf_extension_wfp_filter_context_t, link);

            if (wildcard_filter_context->wildcard == FALSE || wildcard_filter_context->client_context_count == 0 ||
                wildcard_filter_context->context_deleting) {
                // We cannot invoke programs on the wildcard filter context.
                wildcard_filter_context = NULL;
            } else {
                // Found the wildcard filter context. Acquire a reference to it before releasing the provider context
                // lock.
                REFERENCE_FILTER_CONTEXT(wildcard_filter_context);
            }
        }

        // Release the shared spin lock for the provider context.
        ExReleaseSpinLockShared(&provider_context->spin_lock, old_irql);
    }

    // program_result = _net_ebpf_extension_hook_invoke_program2(
    //     filter_context, program_context, process_callback, result, &continue_processing);
    // if ((program_result != EBPF_SUCCESS && program_result != EBPF_OBJECT_NOT_FOUND) || !continue_processing) {
    //     // If we failed to invoke an eBPF program, stop processing and return the error code.
    //     // If any eBPF program returned verdict as block, stop processing and return.
    //     goto Exit;
    // }

    // Acquire shared filter context lock.
    old_irql = ExAcquireSpinLockShared(&filter_context->lock);
    lock_acquired = TRUE;

    // Create a local copy of the client contexts.
    client_count = filter_context->client_context_count;
    for (uint32_t i = 0; i < client_count; i++) {
        // Acquire rundown protection for the client. Rundown for a client only starts once the client has been removed
        // from the list of clients in the filter context. So we should not expect any failure in acquring rundown here.
        // If acquiring rundown fails, bail.
        if (!net_ebpf_extension_hook_client_enter_rundown(filter_context->client_contexts[i])) {
            NET_EBPF_EXT_LOG_MESSAGE(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                "net_ebpf_extension_hook_invoke_programs: Rundown failed for client");
            goto Exit;
        }
        clients[i] = filter_context->client_contexts[i];
    }

    // Release the shared filter context lock.
    ExReleaseSpinLockShared(&filter_context->lock, old_irql);
    lock_acquired = FALSE;
    filter_context = NULL;

    program_result = EBPF_OBJECT_NOT_FOUND;

    // Iterate over all the programs in the array.
    for (uint32_t i = 0; i < client_count; i++) {
        const net_ebpf_extension_hook_client_t* client = clients[i];
        ASSERT(client != NULL);

        program_result = _net_ebpf_extension_hook_invoke_program(client, program_context, result);
        if (program_result != EBPF_SUCCESS) {
            // If we failed to invoke an eBPF program, stop processing and return the error code.
            goto Exit;
        }

        // Invoke callback to see if we should continue processing.
        if (process_callback != NULL) {
            if (!process_callback(*result)) {
                program_result = EBPF_SUCCESS;
                goto Exit;
            }
        }
    }

    // Release rundown protection for all the clients.
    _net_ebpf_extension_release_rundown_for_clients(clients, client_count);

    // // Release the shared filter context lock.
    // ExReleaseSpinLockShared(&filter_context->lock, old_irql);
    // lock_acquired = FALSE;

    if (!wildcard_filter_context) {
        goto Exit;
    }

    // program_result = _net_ebpf_extension_hook_invoke_program2(
    //     wildcard_filter_context, program_context, process_callback, result, &continue_processing);
    // if (program_result != EBPF_SUCCESS) {
    //     // If no programs were found, change the result to EBPF_SUCCESS.
    //     if (program_result == EBPF_OBJECT_NOT_FOUND) {
    //         program_result = EBPF_SUCCESS;
    //     }
    // }

    // Acquire shared lock for wildcard filter context.
    old_irql = ExAcquireSpinLockShared(&wildcard_filter_context->lock);
    wildcard_lock_acquired = TRUE;

    // Create a local copy of the client contexts.
    client_count = wildcard_filter_context->client_context_count;
    for (uint32_t i = 0; i < client_count; i++) {
        // Acquire rundown protection for the client. Rundown for a client only starts once the client has been removed
        // from the list of clients in the filter context. So we should not expect any failure in acquiring rundown
        // here. If acquiring rundown fails, bail.
        if (!net_ebpf_extension_hook_client_enter_rundown(wildcard_filter_context->client_contexts[i])) {
            NET_EBPF_EXT_LOG_MESSAGE(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                "net_ebpf_extension_hook_invoke_programs: Rundown failed for client");
            goto Exit;
        }
        clients[i] = wildcard_filter_context->client_contexts[i];
    }

    // Release the shared lock for wildcard filter context.
    ExReleaseSpinLockShared(&wildcard_filter_context->lock, old_irql);
    wildcard_lock_acquired = FALSE;

    // Iterate over all the programs in the array.
    for (uint32_t i = 0; i < wildcard_filter_context->client_context_count; i++) {
        const net_ebpf_extension_hook_client_t* client = clients[i];
        ASSERT(client != NULL);

        program_result = _net_ebpf_extension_hook_invoke_program(client, program_context, result);
        if (program_result != EBPF_SUCCESS) {
            // If we failed to invoke an eBPF program, stop processing and return the error code.
            goto Exit;
        }

        // Invoke callback to see if we should continue processing.
        if (process_callback != NULL) {
            if (!process_callback(*result)) {
                program_result = EBPF_SUCCESS;
                goto Exit;
            }
        }
    }

Exit:
    if (wildcard_lock_acquired) {
        ExReleaseSpinLockShared(&wildcard_filter_context->lock, old_irql);
    }
    if (lock_acquired) {
        ExReleaseSpinLockShared(&filter_context->lock, old_irql);
    }

    _net_ebpf_extension_release_rundown_for_clients(clients, client_count);

    DEREFERENCE_FILTER_CONTEXT(wildcard_filter_context);
    return program_result;
}

_Requires_lock_held_(provider_context->spin_lock)
    net_ebpf_extension_wfp_filter_context_t* net_ebpf_extension_get_matching_filter_context(
        size_t attach_parameter_size,
        _In_reads_(attach_parameter_size) const void* attach_parameter,
        _In_ net_ebpf_extension_hook_provider_t* provider_context)
{
    net_ebpf_extension_wfp_filter_context_t* matching_context = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    LIST_ENTRY* link = provider_context->filter_context_list.Flink;
    while (link != &provider_context->filter_context_list) {
        net_ebpf_extension_wfp_filter_context_t* next_context =
            (net_ebpf_extension_wfp_filter_context_t*)CONTAINING_RECORD(
                link, net_ebpf_extension_wfp_filter_context_t, link);

        ASSERT(next_context->client_context_count != 0);

        // Get client data from the first client in the filter context.
        const ebpf_extension_data_t* next_context_data = next_context->client_contexts[0]->client_data;
        const void* next_context_attach_parameter = next_context_data->data;
        // Either both the attach parameters should be NULL or they should match.
        if (attach_parameter == NULL && next_context_attach_parameter == NULL) {
            matching_context = next_context;
            break;
        } else if (
            (next_context_attach_parameter != NULL) && (attach_parameter != NULL) &&
            (memcmp(attach_parameter, next_context_attach_parameter, attach_parameter_size) == 0)) {
            matching_context = next_context;
            break;
        }

        link = link->Flink;
    }

    NET_EBPF_EXT_RETURN_POINTER(net_ebpf_extension_wfp_filter_context_t*, matching_context);
}

// _Must_inspect_result_ ebpf_result_t
// net_ebpf_extension_hook_check_attach_parameter(
//     size_t attach_parameter_size,
//     _In_reads_(attach_parameter_size) const void* attach_parameter,
//     _In_reads_(attach_parameter_size) const void* wild_card_attach_parameter,
//     _Inout_ net_ebpf_extension_hook_provider_t* provider_context)
// {
//     ebpf_result_t result = EBPF_SUCCESS;
//     bool using_wild_card_attach_parameter = FALSE;
//     // bool lock_held = FALSE;

//     NET_EBPF_EXT_LOG_ENTRY();

//     if (memcmp(attach_parameter, wild_card_attach_parameter, attach_parameter_size) == 0) {
//         using_wild_card_attach_parameter = TRUE;
//     }

//     // ACQUIRE_PUSH_LOCK_SHARED(&provider_context->lock);
//     // lock_held = TRUE;

//     // TODO: Check all the attached clients and "insert" this client in the correct position.
//     // Then calculate the filter weight for this client.
//     // If no flags specified, then append this in the end.

//     if (using_wild_card_attach_parameter) {
//         // Client requested wild card attach parameter. This will only be allowed if there are no other clients
//         // attached.
//         if (!IsListEmpty(&provider_context->attached_clients_list)) {
//             NET_EBPF_EXT_LOG_MESSAGE(
//                 NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
//                 NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
//                 "Wildcard attach denied as other clients present.");
//             result = EBPF_ACCESS_DENIED;
//             goto Exit;
//         }
//     } else {
//         // Ensure there are no other clients with wild card attach parameter or with the same attach parameter as the
//         // requesting client.

//         LIST_ENTRY* link = provider_context->attached_clients_list.Flink;
//         while (link != &provider_context->attached_clients_list) {
//             net_ebpf_extension_hook_client_t* next_client =
//                 (net_ebpf_extension_hook_client_t*)CONTAINING_RECORD(link, net_ebpf_extension_hook_client_t, link);

//             const ebpf_extension_data_t* next_client_data = next_client->client_data;
//             const void* next_client_attach_parameter =
//                 (next_client_data->data == NULL) ? wild_card_attach_parameter : next_client_data->data;
//             if (((memcmp(wild_card_attach_parameter, next_client_attach_parameter, attach_parameter_size) == 0)) ||
//                 (memcmp(attach_parameter, next_client_attach_parameter, attach_parameter_size) == 0)) {
//                 NET_EBPF_EXT_LOG_MESSAGE(
//                     NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
//                     NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
//                     "Attach denied as other clients present with wildcard/exact attach parameter.");
//                 result = EBPF_ACCESS_DENIED;
//                 goto Exit;
//             }

//             link = link->Flink;
//         }
//     }

// Exit:
//     // if (lock_held) {
//     //     RELEASE_PUSH_LOCK_SHARED(&provider_context->lock);
//     // }

//     NET_EBPF_EXT_RETURN_RESULT(result);
// }

void
_net_ebpf_extension_hook_client_cleanup(_In_opt_ _Frees_ptr_opt_ net_ebpf_extension_hook_client_t* hook_client)
{
    if (hook_client != NULL) {
        if (hook_client->detach_work_item != NULL) {
            IoFreeWorkItem(hook_client->detach_work_item);
        }
        ExFreePool(hook_client);
    }
}

/**
 * @brief Callback invoked when an eBPF hook NPI client (a.k.a eBPF link object) attaches.
 *
 * @param[in] nmr_binding_handle NMR binding between the client module and the provider module.
 * @param[in] provider_context Provider module's context.
 * @param[in] client_registration_instance Client module's registration data.
 * @param[in] client_binding_context Client module's context for binding with provider.
 * @param[in] client_dispatch Client module's dispatch table. Contains the function pointer
 * to invoke the eBPF program.
 * @param[out] provider_binding_context Pointer to provider module's binding context with the client module.
 * @param[out] provider_dispatch Pointer to provider module's dispatch table.
 * @retval STATUS_SUCCESS The operation succeeded.
 * @retval STATUS_NO_MEMORY Failed to allocate provider binding context.
 * @retval STATUS_INVALID_PARAMETER One or more arguments are incorrect.
 */
static NTSTATUS
_net_ebpf_extension_hook_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_hook_provider_t* local_provider_context = (net_ebpf_extension_hook_provider_t*)provider_context;
    net_ebpf_extension_hook_client_t* hook_client = NULL;
    ebpf_extension_program_dispatch_table_t* client_dispatch_table;
    ebpf_result_t result = EBPF_SUCCESS;
    bool push_lock_acquired = FALSE;
    bool spin_lock_acquired = FALSE;
    KIRQL old_irql = PASSIVE_LEVEL;
    ebpf_extension_data_t* client_data = NULL;
    bool is_wild_card_attach_parameter = FALSE;
    net_ebpf_extension_wfp_filter_context_t* new_filter_context = NULL;
    bool rundown_acquired = FALSE;

    NET_EBPF_EXT_LOG_ENTRY();

    if ((provider_binding_context == NULL) || (provider_dispatch == NULL) || (local_provider_context == NULL)) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "Unexpected NULL argument(s). Attach attempt rejected.");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *provider_binding_context = NULL;
    *provider_dispatch = NULL;

    // Validate client data.
    client_data = (ebpf_extension_data_t*)client_registration_instance->NpiSpecificCharacteristics;
    result = local_provider_context->dispatch.validate_client_data(client_data, &is_wild_card_attach_parameter);
    if (result != EBPF_SUCCESS) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "validate_client_data failed. Attach attempt rejected.",
            result);
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    hook_client = (net_ebpf_extension_hook_client_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_hook_client_t), NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_STATUS(
        NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, hook_client, "hook_client", status);

    memset(hook_client, 0, sizeof(net_ebpf_extension_hook_client_t));

    hook_client->counter = InterlockedIncrement(&_hook_client_counter);

    hook_client->detach_work_item = NULL;
    hook_client->nmr_binding_handle = nmr_binding_handle;
    hook_client->client_module_id = client_registration_instance->ModuleId->Guid;
    hook_client->client_binding_context = client_binding_context;
    hook_client->client_data = client_data;
    client_dispatch_table = (ebpf_extension_program_dispatch_table_t*)client_dispatch;
    if (client_dispatch_table == NULL) {
        status = STATUS_INVALID_PARAMETER;
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "client_dispatch_table is NULL. Attach attempt rejected.");
        goto Exit;
    }
    hook_client->invoke_program = client_dispatch_table->ebpf_program_invoke_function;
    hook_client->provider_context = local_provider_context;

    status = _ebpf_ext_attach_init_rundown(hook_client);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "_ebpf_ext_attach_init_rundown failed. Attach attempt rejected.",
            status);
        goto Exit;
    }

    // // Acquire rundown reference on provider context. This will be released when the filter context is deleted.
    // rundown_acquired = ExAcquireRundownProtection(&local_provider_context->rundown.protection);
    // if (!rundown_acquired) {
    //     NET_EBPF_EXT_LOG_MESSAGE(
    //         NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
    //         NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
    //         "ExAcquireRundownProtection failed. Attach attempt rejected.");
    //     status = STATUS_ACCESS_DENIED;
    //     goto Exit;
    // }

    // Acquire passive lock to serialize attach / detach operations.
    ACQUIRE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->push_lock);
    push_lock_acquired = TRUE;

    // Acquire the spin lock to synchronize access to filter_context_list.
    old_irql = ExAcquireSpinLockExclusive(&local_provider_context->spin_lock);
    spin_lock_acquired = TRUE;

    if (local_provider_context->attach_capability == ATTACH_CAPABILITY_SINGLE_ATTACH) {
        // Single attach capability. Only one client can be attached.
        if (!IsListEmpty(&local_provider_context->filter_context_list)) {
            NET_EBPF_EXT_LOG_MESSAGE(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                "Single attach capability. Attach attempt rejected.");
            status = STATUS_ACCESS_DENIED;
            goto Exit;
        }
    } else if (local_provider_context->attach_capability == ATTACH_CAPABILITY_MULTI_ATTACH) {
        // Multi attach capability. Multiple clients can be attached.
        // Check if the attach parameter is already present in the list of filter contexts.
        net_ebpf_extension_wfp_filter_context_t* matching_context = NULL;
        matching_context = net_ebpf_extension_get_matching_filter_context(
            hook_client->client_data->header.size, hook_client->client_data->data, local_provider_context);
        if (matching_context != NULL) {
            // Insert the new client in the filter context.
            result = net_ebpf_ext_add_client_context(matching_context, hook_client);
            if (result != EBPF_SUCCESS) {
                NET_EBPF_EXT_LOG_MESSAGE_UINT32(
                    NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                    "net_ebpf_ext_add_client_context failed. Attach attempt rejected.",
                    result);
                status = STATUS_ACCESS_DENIED;
            } else {
                *provider_binding_context = hook_client;
                hook_client = NULL;
            }
            goto Exit;
        }
    } else if (local_provider_context->attach_capability == ATTACH_CAPABILITY_SINGLE_ATTACH_PER_HOOK) {
        // Exclusive wildcard attach capability. Only one client can be attached with one attach params.
        // In case of wildcard attach parameter, only one client can be attached overall.
        if (is_wild_card_attach_parameter) {
            if (!IsListEmpty(&local_provider_context->filter_context_list)) {
                NET_EBPF_EXT_LOG_MESSAGE(
                    NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                    "Single attach per hook capability. Attach attempt rejected.");
                status = STATUS_ACCESS_DENIED;
                goto Exit;
            }
        } else {
            // Check if the attach parameter is already present in the list of filter contexts.
            net_ebpf_extension_wfp_filter_context_t* matching_context = NULL;
            matching_context = net_ebpf_extension_get_matching_filter_context(
                hook_client->client_data->header.size, hook_client->client_data->data, local_provider_context);

            if (matching_context != NULL) {
                NET_EBPF_EXT_LOG_MESSAGE(
                    NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                    "Only one client allowed. Attach attempt rejected.");
                status = STATUS_ACCESS_DENIED;
                goto Exit;
            }
        }
    }

    // Release the spin lock before creating a new filter context.
    ExReleaseSpinLockExclusive(&local_provider_context->spin_lock, old_irql);
    spin_lock_acquired = FALSE;

    // No matching filter context found. Need to create a new filter context.
    // Acquire rundown reference on provider context. This will be released when the filter context is deleted.
    rundown_acquired = ExAcquireRundownProtection(&local_provider_context->rundown.protection);
    if (!rundown_acquired) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "ExAcquireRundownProtection failed. Attach attempt rejected.");
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    // No matching filter context found. Create a new filter context.
    result = local_provider_context->dispatch.create_filter_context(
        hook_client, local_provider_context, &new_filter_context);
    if (result != EBPF_SUCCESS) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "create_filter_context failed. Attach attempt rejected.",
            result);
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    // If the attach parameter is a wildcard, set the wildcard flag in the filter context.
    if (is_wild_card_attach_parameter) {
        new_filter_context->wildcard = TRUE;
    }

    // Set filter context as provider data in the hook client.
    net_ebpf_extension_hook_client_set_provider_data(hook_client, new_filter_context);

    // Acquire the spin lock to synchronize access to filter_context_list.
    old_irql = ExAcquireSpinLockExclusive(&local_provider_context->spin_lock);
    spin_lock_acquired = TRUE;

    // Insert the new filter context in the list of filter contexts.
    // In case of wildcard attach parameter, insert at the tail of the list.
    if (is_wild_card_attach_parameter) {
        InsertTailList(&local_provider_context->filter_context_list, &new_filter_context->link);
    } else {
        InsertHeadList(&local_provider_context->filter_context_list, &new_filter_context->link);
    }
    new_filter_context->initialized = TRUE;
    new_filter_context = NULL;

    *provider_binding_context = hook_client;
    hook_client = NULL;

Exit:
    if (local_provider_context) {
        if (spin_lock_acquired) {
            ExReleaseSpinLockExclusive(&local_provider_context->spin_lock, old_irql);
        }
        if (push_lock_acquired) {
            RELEASE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->push_lock);
        }

        local_provider_context->dispatch.delete_filter_context(new_filter_context);
    }

    _net_ebpf_extension_hook_client_cleanup(hook_client);

    if (status != STATUS_SUCCESS) {
        if (rundown_acquired) {
            ExReleaseRundownProtection(&local_provider_context->rundown.protection);
        }
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

static void
_net_ebpf_ext_remove_filter_context_from_provider(
    _In_ net_ebpf_extension_hook_provider_t* provider_context,
    _In_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    KIRQL old_irql = PASSIVE_LEVEL;
    bool spin_lock_acquired = FALSE;

    NET_EBPF_EXT_LOG_ENTRY();

    // Acquire the spin lock to synchronize access to filter_context_list.
    old_irql = ExAcquireSpinLockExclusive(&provider_context->spin_lock);
    spin_lock_acquired = TRUE;

    RemoveEntryList(&filter_context->link);

    ExReleaseSpinLockExclusive(&provider_context->spin_lock, old_irql);
    spin_lock_acquired = FALSE;

    // Release the filter context.
    provider_context->dispatch.delete_filter_context(filter_context);

    NET_EBPF_EXT_LOG_EXIT();
}

/**
 * @brief Callback invoked when a hook NPI client (a.k.a. eBPF link object) detaches.
 *
 * @param[in] provider_binding_context Provider module's context for binding with the client.
 * @retval STATUS_SUCCESS The operation succeeded.
 * @retval STATUS_PENDING The operation is pending completion.
 * @retval STATUS_INVALID_PARAMETER One or more parameters are invalid.
 */
static NTSTATUS
_net_ebpf_extension_hook_provider_detach_client(_In_ const void* provider_binding_context)
{
    NTSTATUS status = STATUS_PENDING;
    net_ebpf_extension_hook_provider_t* local_provider_context = NULL;
    bool push_lock_acquired = FALSE;
    // bool spin_lock_acquired = FALSE;
    net_ebpf_extension_wfp_filter_context_t* filter_context = NULL;
    // KIRQL old_irql = PASSIVE_LEVEL;

    NET_EBPF_EXT_LOG_ENTRY();

    net_ebpf_extension_hook_client_t* local_client_context =
        (net_ebpf_extension_hook_client_t*)provider_binding_context;

    if (local_client_context == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "local_client_context is NULL. Detach attempt rejected.");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    local_provider_context = local_client_context->provider_context;

    // Acquire push lock to serialize attach / detach operations.
    ACQUIRE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->push_lock);
    push_lock_acquired = TRUE;

    // ANUSA TODO: Move the below block of code (line 657 - 673) to a separate function.

    filter_context = (net_ebpf_extension_wfp_filter_context_t*)local_client_context->provider_data;

    // Remove the client from the filter context.
    net_ebpf_ext_remove_client_context(filter_context, local_client_context);

    // If the filter context is empty, remove it from the list of filter contexts.
    // Note that we can access client_context_count as we still have push lock acquired which serializes
    // all attach/detach operations on this provider.
    if (filter_context->client_context_count == 0) {
        _net_ebpf_ext_remove_filter_context_from_provider(local_provider_context, filter_context);
    }

    // Queue a work item to delete the client context.
    IoQueueWorkItem(
        local_client_context->detach_work_item,
        _net_ebpf_extension_detach_client_completion,
        DelayedWorkQueue,
        (void*)local_client_context);

Exit:
    if (local_provider_context) {
        if (push_lock_acquired) {
            RELEASE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->push_lock);
        }
    }
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

static void
_net_ebpf_extension_hook_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context)
{
    if (provider_binding_context != NULL) {
        ExFreePool(provider_binding_context);
    }
}

void
net_ebpf_extension_hook_provider_unregister(
    _In_opt_ _Frees_ptr_opt_ net_ebpf_extension_hook_provider_t* provider_context)
{
    NET_EBPF_EXT_LOG_ENTRY();
    if (provider_context != NULL) {
        if (provider_context->nmr_provider_handle != NULL) {
            NTSTATUS status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
            if (status == STATUS_PENDING) {

                // Wait for clients to detach.
                NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
            } else {
                NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                    NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "NmrDeregisterProvider", status);
            }
        }
        // Wait for rundown reference to become 0. This will ensure all filter contexts, hence all
        // filter are cleaned up.
        _ebpf_ext_attach_wait_for_rundown(&provider_context->rundown);
        ExFreePool(provider_context);
    }
    NET_EBPF_EXT_LOG_EXIT();
}

NTSTATUS
net_ebpf_extension_hook_provider_register(
    _In_ const net_ebpf_extension_hook_provider_parameters_t* parameters,
    _In_ const net_ebpf_extension_hook_provider_dispatch_table_t* dispatch,
    net_ebpf_extension_hook_attach_capability_t attach_capability,
    _In_opt_ const void* custom_data,
    _Outptr_ net_ebpf_extension_hook_provider_t** provider_context)
{
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_hook_provider_t* local_provider_context = NULL;
    NPI_PROVIDER_CHARACTERISTICS* characteristics;

    NET_EBPF_EXT_LOG_ENTRY();
    local_provider_context = (net_ebpf_extension_hook_provider_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_hook_provider_t), NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_STATUS(
        NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, local_provider_context, "local_provider_context", status);

    memset(local_provider_context, 0, sizeof(net_ebpf_extension_hook_provider_t));
    ExInitializePushLock(&local_provider_context->push_lock);
    InitializeListHead(&local_provider_context->filter_context_list);

    characteristics = &local_provider_context->characteristics;
    characteristics->Length = sizeof(NPI_PROVIDER_CHARACTERISTICS);
    characteristics->ProviderAttachClient =
        (PNPI_PROVIDER_ATTACH_CLIENT_FN)_net_ebpf_extension_hook_provider_attach_client;
    characteristics->ProviderDetachClient =
        (PNPI_PROVIDER_DETACH_CLIENT_FN)_net_ebpf_extension_hook_provider_detach_client;
    characteristics->ProviderCleanupBindingContext = _net_ebpf_extension_hook_provider_cleanup_binding_context;
    characteristics->ProviderRegistrationInstance.Size = sizeof(NPI_REGISTRATION_INSTANCE);
    characteristics->ProviderRegistrationInstance.NpiId = &EBPF_HOOK_EXTENSION_IID;
    characteristics->ProviderRegistrationInstance.NpiSpecificCharacteristics = parameters->provider_data;
    characteristics->ProviderRegistrationInstance.ModuleId = parameters->provider_module_id;

    local_provider_context->dispatch = *dispatch;
    // local_provider_context->dispatch.create_filter_context = create_filter_context;
    // local_provider_context->dispatch.validate_client_data = validate_client_data;
    // local_provider_context->attach_callback = attach_callback;
    // local_provider_context->detach_callback = detach_callback;
    local_provider_context->custom_data = custom_data;
    local_provider_context->attach_capability = attach_capability;

    status = NmrRegisterProvider(characteristics, local_provider_context, &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status)) {

        // The docs don't mention the (out) handle status on failure, so explicitly mark it as invalid.
        local_provider_context->nmr_provider_handle = NULL;
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "NmrRegisterProvider", status);
        goto Exit;
    }

    // Initialize rundown protection for the provider context.
    ExInitializeRundownProtection(&local_provider_context->rundown.protection);
    local_provider_context->rundown.rundown_occurred = FALSE;

    *provider_context = local_provider_context;
    local_provider_context = NULL;

Exit:
    if (!NT_SUCCESS(status)) {
        net_ebpf_extension_hook_provider_unregister(local_provider_context);
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

// net_ebpf_extension_hook_client_t*
// net_ebpf_extension_hook_get_attached_client(_Inout_ net_ebpf_extension_hook_provider_t* provider_context)
// {
//     net_ebpf_extension_hook_client_t* client_context = NULL;
//     // ACQUIRE_PUSH_LOCK_SHARED(&provider_context->lock);
//     if (!IsListEmpty(&provider_context->attached_clients_list)) {
//         client_context = (net_ebpf_extension_hook_client_t*)CONTAINING_RECORD(
//             provider_context->attached_clients_list.Flink, net_ebpf_extension_hook_client_t, link);
//     }
//     // RELEASE_PUSH_LOCK_SHARED(&provider_context->lock);
//     return client_context;
// }

// _Requires_lock_held_(provider_context->spin_lock)
// static net_ebpf_extension_wfp_filter_context_t* _net_ebpf_extension_hook_get_next_filter_context(
//     _In_ const net_ebpf_extension_wfp_filter_context_t* filter_context,
//     _In_ const net_ebpf_extension_hook_provider_t* provider_context)
// {
//     net_ebpf_extension_wfp_filter_context_t* next_context = NULL;
//     if (filter_context == NULL) {
//         // Return the first context (if any).
//         if (!IsListEmpty(&provider_context->filter_context_list)) {
//             next_context = (net_ebpf_extension_wfp_filter_context_t*)CONTAINING_RECORD(
//                 provider_context->filter_context_list.Flink, net_ebpf_extension_wfp_filter_context_t, link);
//         }
//     } else {
//         // Return the next client, unless this is the last one.
//         if (filter_context->link.Flink != &provider_context->filter_context_list) {
//             next_context = (net_ebpf_extension_wfp_filter_context_t*)CONTAINING_RECORD(
//                 next_context->link.Flink, net_ebpf_extension_wfp_filter_context_t, link);
//         }
//     }

//     return next_context;
// }

// KIRQL
// net_ebpf_extension_hook_acquire_spin_lock_shared(_Inout_ net_ebpf_extension_hook_provider_t* provider_context)
// {
//     return ExAcquireSpinLockShared(&provider_context->spin_lock);
// }

// void
// net_ebpf_extension_hook_release_spin_lock_shared(
//     _Inout_ net_ebpf_extension_hook_provider_t* provider_context, KIRQL old_irql)
// {
//     ExReleaseSpinLockShared(&provider_context->spin_lock, old_irql);
// }
