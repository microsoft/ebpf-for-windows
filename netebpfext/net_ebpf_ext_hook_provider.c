// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_extension_uuids.h"
#include "net_ebpf_ext_hook_provider.h"

#define NET_EBPF_EXT_STACK_EXPANSION_SIZE 1024 * 10

typedef struct _net_ebpf_ext_hook_client_rundown
{
    EX_RUNDOWN_REF protection;
    bool rundown_occurred;
} net_ebpf_ext_hook_rundown_t;

struct _net_ebpf_extension_hook_provider;

/**
 * @brief Data structure representing a hook NPI client (attached eBPF program). This is returned
 * as the provider binding context in the NMR client attach callback.
 */
typedef struct _net_ebpf_extension_hook_client
{
    HANDLE nmr_binding_handle;                     ///< NMR binding handle.
    GUID client_module_id;                         ///< NMR module Id.
    const void* client_binding_context;            ///< Client supplied context to be passed when invoking eBPF program.
    const ebpf_extension_data_t* client_data;      ///< Client supplied attach parameters.
    ebpf_program_invoke_function_t invoke_program; ///< Pointer to function to invoke eBPF program.
    void* provider_data;                 ///< Opaque pointer to hook specific data associated with this client.
    PIO_WORKITEM detach_work_item;       ///< Pointer to IO work item that is invoked to detach the client.
    net_ebpf_ext_hook_rundown_t rundown; ///< Pointer to rundown object used to synchronize detach operation.
} net_ebpf_extension_hook_client_t;

typedef struct _net_ebpf_extension_hook_provider
{
    NPI_PROVIDER_CHARACTERISTICS characteristics;                  ///< NPI Provider characteristics.
    net_ebpf_ext_hook_rundown_t rundown;                           ///< Rundown reference for the hook provider.
    HANDLE nmr_provider_handle;                                    ///< NMR binding handle.
    EX_PUSH_LOCK lock;                                             ///< Lock for serializing attach / detach calls.
    net_ebpf_extension_hook_provider_dispatch_table_t dispatch;    ///< Hook specific dispatch table.
    net_ebpf_extension_hook_attach_capability_t attach_capability; ///< Attach capability for specific hook provider.
    const void* custom_data; ///< Opaque pointer to hook specific data associated for this provider.
    _Guarded_by_(lock)
        LIST_ENTRY filter_context_list; ///< Linked list of filter contexts that are attached to this provider.
} net_ebpf_extension_hook_provider_t;

typedef struct _net_ebpf_extension_invoke_programs_parameters
{
    net_ebpf_extension_wfp_filter_context_t* filter_context;
    void* program_context;
    uint32_t verdict;
    ebpf_result_t result;
} net_ebpf_extension_invoke_programs_parameters_t;

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

net_ebpf_extension_hook_attach_capability_t
net_ebpf_extension_hook_provider_get_attach_capability(_In_ const net_ebpf_extension_hook_provider_t* provider_context)
{
    return provider_context->attach_capability;
}

__forceinline _Must_inspect_result_ static ebpf_result_t
_net_ebpf_extension_hook_invoke_single_program(
    _In_ const net_ebpf_extension_hook_client_t* client, _Inout_ void* context, _Out_ uint32_t* result)
{
    ebpf_program_invoke_function_t invoke_program = client->invoke_program;
    const void* client_binding_context = client->client_binding_context;

    return invoke_program(client_binding_context, context, result);
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

ebpf_result_t
net_ebpf_extension_hook_invoke_programs(
    _Inout_ void* program_context, _In_ net_ebpf_extension_wfp_filter_context_t* filter_context, _Out_ uint32_t* result)
{
    ebpf_result_t program_result = EBPF_SUCCESS;
    KIRQL old_irql = PASSIVE_LEVEL;
    bool lock_acquired = FALSE;
    uint32_t client_count = 0;
    net_ebpf_extension_hook_client_t* clients[NET_EBPF_EXT_MAX_CLIENTS_PER_HOOK_MULTI_ATTACH] = {0};
    const net_ebpf_extension_hook_process_verdict process_verdict =
        filter_context->provider_context->dispatch.process_verdict;

    *result = 0;

    // Acquire shared filter context lock.
    old_irql = ExAcquireSpinLockShared(&filter_context->lock);
    lock_acquired = TRUE;

    // Create a local copy of the client contexts.
    client_count = filter_context->client_context_count;
    for (uint32_t i = 0; i < client_count; i++) {
        // Acquire rundown protection for the client. Rundown for a client only starts once the client has been removed
        // from the list of clients in the filter context. So we should not expect any failure in acquiring rundown
        // here. If acquiring rundown fails, bail.
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
        ASSERT(clients[i] != NULL);

        program_result = _net_ebpf_extension_hook_invoke_single_program(clients[i], program_context, result);
        if (program_result != EBPF_SUCCESS) {
            // If we failed to invoke an eBPF program, stop processing and return the error code.
            goto Exit;
        }

        // Invoke callback to see if we should continue processing.
        if (process_verdict != NULL) {
            if (!process_verdict(program_context, *result)) {
                program_result = EBPF_SUCCESS;
                goto Exit;
            }
        }
    }

Exit:
    if (lock_acquired) {
        ExReleaseSpinLockShared(&filter_context->lock, old_irql);
    }

    _net_ebpf_extension_release_rundown_for_clients(clients, client_count);
    return program_result;
}

_Function_class_(EXPAND_STACK_CALLOUT) static void _net_ebpf_extension_invoke_programs_callout(_Inout_ void* context)
{
    net_ebpf_extension_invoke_programs_parameters_t* parameters =
        (net_ebpf_extension_invoke_programs_parameters_t*)context;

    ebpf_result_t result = net_ebpf_extension_hook_invoke_programs(
        parameters->program_context, parameters->filter_context, &parameters->verdict);

    parameters->result = result;
}

ebpf_result_t
net_ebpf_extension_hook_expand_stack_and_invoke_programs(
    _Inout_ void* program_context,
    _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _Out_ uint32_t* result)
{
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_invoke_programs_parameters_t invoke_parameters = {0};
    invoke_parameters.filter_context = filter_context;
    invoke_parameters.program_context = (void*)program_context;

#pragma warning(push)
#pragma warning(disable : 28160) //  Error annotation: DISPATCH_LEVEL is only supported on Windows 7 or later.
    // Expand the stack and call the program.
    status = KeExpandKernelStackAndCalloutEx(
        (PEXPAND_STACK_CALLOUT)_net_ebpf_extension_invoke_programs_callout,
        &invoke_parameters,
        NET_EBPF_EXT_STACK_EXPANSION_SIZE,
        FALSE,
        NULL);
    if (status != STATUS_SUCCESS) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "KeExpandKernelStackAndCalloutEx", status);
        return EBPF_FAILED;
    }
#pragma warning(pop)

    *result = invoke_parameters.verdict;

    return invoke_parameters.result;
}

_Requires_lock_held_(provider_context->lock)
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
    bool provider_lock_acquired = FALSE;
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

    status = _ebpf_ext_attach_init_rundown(hook_client);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "_ebpf_ext_attach_init_rundown failed. Attach attempt rejected.",
            status);
        goto Exit;
    }

    // Acquire passive lock to serialize attach / detach operations.
    ACQUIRE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->lock);
    provider_lock_acquired = TRUE;

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
    } else if (local_provider_context->attach_capability == ATTACH_CAPABILITY_MULTI_ATTACH_WITH_WILDCARD) {
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
        if (provider_lock_acquired) {
            RELEASE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->lock);
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

_Requires_exclusive_lock_held_(provider_context->lock) static void _net_ebpf_ext_remove_filter_context_from_provider(
    _In_ net_ebpf_extension_hook_provider_t* provider_context,
    _In_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    NET_EBPF_EXT_LOG_ENTRY();

    RemoveEntryList(&filter_context->link);

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
    bool provider_lock_acquired = FALSE;
    net_ebpf_extension_wfp_filter_context_t* filter_context = NULL;

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

    filter_context = (net_ebpf_extension_wfp_filter_context_t*)local_client_context->provider_data;
    local_provider_context = (net_ebpf_extension_hook_provider_t*)filter_context->provider_context;

    // Acquire push lock to serialize attach / detach operations.
    ACQUIRE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->lock);
    provider_lock_acquired = TRUE;

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
        if (provider_lock_acquired) {
            RELEASE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->lock);
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
    ExInitializePushLock(&local_provider_context->lock);
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
