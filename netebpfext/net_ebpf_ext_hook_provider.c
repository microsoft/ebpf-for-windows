// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <wdm.h>
#include "net_ebpf_ext_hook_provider.h"
#include "ebpf_extension_uuids.h"

/**
 * @brief Pointer to function to invoke the eBPF program associated with the hook NPI client.
 * This is the only function in the client's dispatch table.
 */
typedef ebpf_result_t (*ebpf_invoke_program_function_t)(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result);

typedef struct _net_ebpf_ext_hook_client_rundown
{
    bool rundown_occurred;
    struct
    {
        KDPC rundown_dpc;
        KEVENT rundown_wait;
    } dispatch;
    struct
    {
        EX_PUSH_LOCK lock;
    } passive;
} net_ebpf_ext_hook_client_rundown_t;

struct _net_ebpf_extension_hook_provider;

/**
 * @brief Data structure representing a hook NPI client (attached eBPF program). This is returned
 * as the provider binding context in the NMR client attach callback.
 */
typedef struct _net_ebpf_extension_hook_client
{
    LIST_ENTRY link;                               ///< Link to next client (if any).
    HANDLE nmr_binding_handle;                     ///< NMR binding handle.
    GUID client_module_id;                         ///< NMR module Id.
    const void* client_binding_context;            ///< Client supplied context to be passed when invoking eBPF program.
    const ebpf_extension_data_t* client_data;      ///< Client supplied attach parameters.
    ebpf_invoke_program_function_t invoke_program; ///< Pointer to function to invoke eBPF program.
    void* provider_data; ///< Opaque pointer to hook specific data associated with this client.
    struct _net_ebpf_extension_hook_provider* provider_context; ///< Pointer to the hook NPI provider context.
    net_ebpf_extension_hook_execution_t execution_type;         ///< eBPF hook execution type - PASSIVE or DISPATCH.
    PIO_WORKITEM detach_work_item;              ///< Pointer to IO work item that is invoked to detach the client.
    net_ebpf_ext_hook_client_rundown_t rundown; ///< Pointer to rundown object used to synchronize detach operation.
} net_ebpf_extension_hook_client_t;

typedef struct _net_ebpf_extension_hook_clients_list
{
    EX_PUSH_LOCK lock;
    LIST_ENTRY attached_clients_list;
} net_ebpf_extension_hook_clients_list_t;

typedef struct _net_ebpf_extension_hook_provider
{
    NPI_PROVIDER_CHARACTERISTICS characteristics;             ///< NPI Provider characteristics.
    HANDLE nmr_provider_handle;                               ///< NMR binding handle.
    net_ebpf_extension_hook_execution_t execution_type;       ///< Hook execution type (PASSIVE or DISPATCH).
    EX_PUSH_LOCK lock;                                        ///< Lock for synchronization.
    net_ebpf_extension_hook_on_client_attach attach_callback; /*!< Pointer to hook specific callback to be invoked
                                                              when a client attaches. */
    net_ebpf_extension_hook_on_client_detach detach_callback; /*!< Pointer to hook specific callback to be invoked
                                                              when a client detaches. */
    const void* custom_data; ///< Opaque pointer to hook specific data associated for this provider.
    _Guarded_by_(lock)
        LIST_ENTRY attached_clients_list; ///< Linked list of hook NPI clients that are attached to this provider.
} net_ebpf_extension_hook_provider_t;

#define _ACQUIRE_PUSH_LOCK(lock, mode) \
    {                                  \
        KeEnterCriticalRegion();       \
        ExAcquirePushLock##mode(lock); \
    }

#define _RELEASE_PUSH_LOCK(lock, mode) \
    {                                  \
        ExReleasePushLock##mode(lock); \
        KeLeaveCriticalRegion();       \
    }

#define ACQUIRE_PUSH_LOCK_EXCLUSIVE(lock) _ACQUIRE_PUSH_LOCK(lock, Exclusive)
#define ACQUIRE_PUSH_LOCK_SHARED(lock) _ACQUIRE_PUSH_LOCK(lock, Shared)

#define RELEASE_PUSH_LOCK_EXCLUSIVE(lock) _RELEASE_PUSH_LOCK(lock, Exclusive)
#define RELEASE_PUSH_LOCK_SHARED(lock) _RELEASE_PUSH_LOCK(lock, Shared)

static _Function_class_(KDEFERRED_ROUTINE) _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_requires_min_(DISPATCH_LEVEL)
    _IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ void _ebpf_ext_attach_rundown(
        _In_ KDPC* dpc,
        _In_opt_ void* deferred_context,
        _In_opt_ void* system_argument_1,
        _In_opt_ void* system_argument_2)
{
    net_ebpf_ext_hook_client_rundown_t* rundown = (net_ebpf_ext_hook_client_rundown_t*)deferred_context;

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(system_argument_1);
    UNREFERENCED_PARAMETER(system_argument_2);
    if (rundown)
        KeSetEvent(&rundown->dispatch.rundown_wait, 0, FALSE);
}

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
    net_ebpf_ext_hook_client_rundown_t* rundown = &hook_client->rundown;
    net_ebpf_extension_hook_execution_t execution_type = hook_client->execution_type;

    //
    // Allocate work item for client detach processing.
    //
    hook_client->detach_work_item = IoAllocateWorkItem(_net_ebpf_ext_driver_device_object);
    if (hook_client->detach_work_item == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    if (execution_type == EXECUTION_PASSIVE) {
        ExInitializePushLock(&rundown->passive.lock);
    } else {
        KeInitializeEvent(&(rundown->dispatch.rundown_wait), SynchronizationEvent, FALSE);
        KeInitializeDpc(&(rundown->dispatch.rundown_dpc), _ebpf_ext_attach_rundown, rundown);
    }
    rundown->rundown_occurred = FALSE;

Exit:
    return status;
}

/**
 * @brief Block execution of the thread until all invocations are completed.
 *
 * @param[in, out] rundown Rundown object to wait for.
 * @param[in]  execution_type Execution type for the hook (passive or dispatch).
 *
 */
static void
_ebpf_ext_attach_wait_for_rundown(
    _Inout_ net_ebpf_ext_hook_client_rundown_t* rundown, net_ebpf_extension_hook_execution_t execution_type)
{
    rundown->rundown_occurred = TRUE;
    if (execution_type == EXECUTION_PASSIVE) {
        ACQUIRE_PUSH_LOCK_EXCLUSIVE(&rundown->passive.lock);
        RELEASE_PUSH_LOCK_EXCLUSIVE(&rundown->passive.lock);
    } else {
        // Queue a DPC to each CPU and wait for it to run.
        // After it has run on each CPU we can be sure that no
        // DPC is busy processing a hook.
        uint32_t maximum_processor = KeQueryMaximumProcessorCount();
        uint32_t processor;
        for (processor = 0; processor < maximum_processor; processor++) {
            KeSetTargetProcessorDpc(&rundown->dispatch.rundown_dpc, (uint8_t)processor);
            if (KeInsertQueueDpc(&rundown->dispatch.rundown_dpc, NULL, NULL)) {
                KeWaitForSingleObject(&rundown->dispatch.rundown_wait, Executive, KernelMode, FALSE, NULL);
            }
        }
    }
}

IO_WORKITEM_ROUTINE _net_ebpf_extension_detach_client_completion;
#pragma alloc_text(PAGE, _net_ebpf_extension_detach_client_completion)

/**
 * @brief IO work item routine callback that waits on client rundown to complete.
 *
 * @param[in] device_object IO Device object.
 * @param[in] context Pointer to work item context.
 *
 */
void
_net_ebpf_extension_detach_client_completion(_In_ PDEVICE_OBJECT device_object, _In_opt_ void* context)
{
    net_ebpf_extension_hook_client_t* hook_client = (net_ebpf_extension_hook_client_t*)context;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(device_object);

    ASSERT(hook_client != NULL);
    _Analysis_assume_(hook_client != NULL);

    // Wait for any in progress callbacks to complete.
    _ebpf_ext_attach_wait_for_rundown(&hook_client->rundown, hook_client->execution_type);

    NmrProviderDetachClientComplete(hook_client->nmr_binding_handle);

    IoFreeWorkItem(hook_client->detach_work_item);
}

_Acquires_lock_(hook_client) bool net_ebpf_extension_hook_client_enter_rundown(
    _Inout_ net_ebpf_extension_hook_client_t* hook_client, net_ebpf_extension_hook_execution_t execution_type)
{
    net_ebpf_ext_hook_client_rundown_t* rundown = &hook_client->rundown;
    if (execution_type == EXECUTION_PASSIVE) {
        ACQUIRE_PUSH_LOCK_SHARED(&rundown->passive.lock);
    }

    return (rundown->rundown_occurred == FALSE);
}

_Releases_lock_(hook_client) void net_ebpf_extension_hook_client_leave_rundown(
    _Inout_ net_ebpf_extension_hook_client_t* hook_client, net_ebpf_extension_hook_execution_t execution_type)
{
    net_ebpf_ext_hook_client_rundown_t* rundown = &hook_client->rundown;
    if (execution_type == EXECUTION_PASSIVE) {
        _Analysis_assume_lock_held_(&rundown->passive.lock);
        RELEASE_PUSH_LOCK_SHARED(&rundown->passive.lock);
    }
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

ebpf_result_t
net_ebpf_extension_hook_invoke_program(
    _In_ const net_ebpf_extension_hook_client_t* client, _In_ void* context, _Out_ uint32_t* result)
{
    ebpf_invoke_program_function_t invoke_program = client->invoke_program;
    const void* client_binding_context = client->client_binding_context;

    return invoke_program(client_binding_context, context, result);
}

ebpf_result_t
net_ebpf_extension_hook_check_attach_parameter(
    size_t attach_parameter_size,
    _In_reads_(attach_parameter_size) const void* attach_parameter,
    _In_reads_(attach_parameter_size) const void* wild_card_attach_parameter,
    _In_ net_ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    bool using_wild_card_attach_parameter = FALSE;
    bool lock_held = FALSE;

    if (memcmp(attach_parameter, wild_card_attach_parameter, attach_parameter_size) == 0)
        using_wild_card_attach_parameter = TRUE;

    ACQUIRE_PUSH_LOCK_SHARED(&provider_context->lock);
    lock_held = TRUE;
    if (using_wild_card_attach_parameter) {
        // Client requested wild card attach parameter. This will only be allowed if there are no other clients
        // attached.
        if (!IsListEmpty(&provider_context->attached_clients_list)) {
            result = EBPF_ACCESS_DENIED;
            goto Exit;
        }
    } else {
        // Ensure there are no other clients with wild card attach parameter or with the same attach parameter as the
        // requesting client.

        LIST_ENTRY* link = provider_context->attached_clients_list.Flink;
        while (link != &provider_context->attached_clients_list) {
            net_ebpf_extension_hook_client_t* next_client =
                (net_ebpf_extension_hook_client_t*)CONTAINING_RECORD(link, net_ebpf_extension_hook_client_t, link);

            const ebpf_extension_data_t* next_client_data = next_client->client_data;
            void* next_client_attach_parameter =
                (next_client_data->data == NULL) ? wild_card_attach_parameter : next_client_data->data;
            if (((memcmp(wild_card_attach_parameter, next_client_attach_parameter, attach_parameter_size) == 0)) ||
                (memcmp(attach_parameter, next_client_attach_parameter, attach_parameter_size) == 0)) {
                result = EBPF_ACCESS_DENIED;
                goto Exit;
            }

            link = link->Flink;
        }
    }

Exit:
    if (lock_held)
        RELEASE_PUSH_LOCK_SHARED(&provider_context->lock);

    return result;
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
    _In_ void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_hook_provider_t* local_provider_context = (net_ebpf_extension_hook_provider_t*)provider_context;
    net_ebpf_extension_hook_client_t* hook_client = NULL;
    ebpf_extension_dispatch_table_t* client_dispatch_table;
    ebpf_result_t result = EBPF_SUCCESS;

    if ((provider_binding_context == NULL) || (provider_dispatch == NULL) || (local_provider_context == NULL)) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *provider_binding_context = NULL;
    *provider_dispatch = NULL;

    hook_client = (net_ebpf_extension_hook_client_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_hook_client_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (hook_client == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }
    memset(hook_client, 0, sizeof(net_ebpf_extension_hook_client_t));

    hook_client->nmr_binding_handle = nmr_binding_handle;
    hook_client->client_module_id = client_registration_instance->ModuleId->Guid;
    hook_client->client_binding_context = client_binding_context;
    hook_client->client_data = client_registration_instance->NpiSpecificCharacteristics;
    client_dispatch_table = (ebpf_extension_dispatch_table_t*)client_dispatch;
    if (client_dispatch_table == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    hook_client->invoke_program = (ebpf_invoke_program_function_t)client_dispatch_table->function[0];
    hook_client->provider_context = local_provider_context;
    hook_client->execution_type = local_provider_context->execution_type;

    // Invoke the hook specific callback to process client attach.
    result = local_provider_context->attach_callback(hook_client, local_provider_context);

    if (result == EBPF_SUCCESS) {
        status = _ebpf_ext_attach_init_rundown(hook_client);
        if (status == STATUS_SUCCESS) {
            ACQUIRE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->lock);
            InsertTailList(&local_provider_context->attached_clients_list, &hook_client->link);
            RELEASE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->lock);
        }
    } else {
        status = STATUS_ACCESS_DENIED;
    }

Exit:

    if (NT_SUCCESS(status)) {
        *provider_binding_context = hook_client;
        hook_client = NULL;
    } else {
        if (hook_client)
            ExFreePool(hook_client);
    }

    return status;
}

/**
 * @brief Callback invoked when a hook NPI client (a.k.a eBPF link object) detaches.
 *
 * @param[in] provider_binding_context Provider module's context for binding with the client.
 * @retval STATUS_SUCCESS The operation succeeded.
 * @retval STATUS_INVALID_PARAMETER One or more parameters are invalid.
 */
static NTSTATUS
_net_ebpf_extension_hook_provider_detach_client(_In_ void* provider_binding_context)
{
    NTSTATUS status = STATUS_PENDING;

    net_ebpf_extension_hook_client_t* local_client_context =
        (net_ebpf_extension_hook_client_t*)provider_binding_context;

    net_ebpf_extension_hook_provider_t* local_provider_context = local_client_context->provider_context;

    if (local_client_context == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Invoke hook specific handler for processing client detach.
    local_provider_context->detach_callback(local_client_context);

    ACQUIRE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->lock);
    RemoveEntryList(&local_client_context->link);
    RELEASE_PUSH_LOCK_EXCLUSIVE(&local_provider_context->lock);

    IoQueueWorkItem(
        local_client_context->detach_work_item,
        _net_ebpf_extension_detach_client_completion,
        DelayedWorkQueue,
        (PVOID)local_client_context);

Exit:
    return status;
}

static void
_net_ebpf_extension_hook_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context)
{
    ExFreePool(provider_binding_context);
}

void
net_ebpf_extension_hook_provider_unregister(_Frees_ptr_opt_ net_ebpf_extension_hook_provider_t* provider_context)
{
    if (provider_context != NULL) {
        NTSTATUS status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
        if (status == STATUS_PENDING)
            // Wait for clients to detach.
            NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
        ExFreePool(provider_context);
    }
}

NTSTATUS
net_ebpf_extension_hook_provider_register(
    _In_ const net_ebpf_extension_hook_provider_parameters_t* parameters,
    _In_ net_ebpf_extension_hook_on_client_attach attach_callback,
    _In_ net_ebpf_extension_hook_on_client_detach detach_callback,
    _In_opt_ const void* custom_data,
    _Outptr_ net_ebpf_extension_hook_provider_t** provider_context)
{
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_hook_provider_t* local_provider_context = NULL;
    NPI_PROVIDER_CHARACTERISTICS* characteristics;

    local_provider_context = (net_ebpf_extension_hook_provider_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_hook_provider_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (local_provider_context == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }
    memset(local_provider_context, 0, sizeof(net_ebpf_extension_hook_provider_t));
    ExInitializePushLock(&local_provider_context->lock);
    InitializeListHead(&local_provider_context->attached_clients_list);

    characteristics = &local_provider_context->characteristics;
    characteristics->Length = sizeof(NPI_PROVIDER_CHARACTERISTICS);
    characteristics->ProviderAttachClient = _net_ebpf_extension_hook_provider_attach_client;
    characteristics->ProviderDetachClient = _net_ebpf_extension_hook_provider_detach_client;
    characteristics->ProviderCleanupBindingContext = _net_ebpf_extension_hook_provider_cleanup_binding_context;
    characteristics->ProviderRegistrationInstance.Size = sizeof(NPI_REGISTRATION_INSTANCE);
    characteristics->ProviderRegistrationInstance.NpiId = &EBPF_HOOK_EXTENSION_IID;
    characteristics->ProviderRegistrationInstance.NpiSpecificCharacteristics = parameters->provider_data;
    characteristics->ProviderRegistrationInstance.ModuleId = parameters->provider_module_id;

    local_provider_context->execution_type = parameters->execution_type;
    local_provider_context->attach_callback = attach_callback;
    local_provider_context->detach_callback = detach_callback;
    local_provider_context->custom_data = custom_data;

    status = NmrRegisterProvider(characteristics, local_provider_context, &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status))
        goto Exit;

    *provider_context = local_provider_context;
    local_provider_context = NULL;

Exit:
    if (!NT_SUCCESS(status))
        net_ebpf_extension_hook_provider_unregister(local_provider_context);

    return status;
}

net_ebpf_extension_hook_client_t*
net_ebpf_extension_hook_get_attached_client(_In_ net_ebpf_extension_hook_provider_t* provider_context)
{
    net_ebpf_extension_hook_client_t* client_context = NULL;
    ACQUIRE_PUSH_LOCK_SHARED(&provider_context->lock);
    if (!IsListEmpty(&provider_context->attached_clients_list))
        client_context = (net_ebpf_extension_hook_client_t*)CONTAINING_RECORD(
            provider_context->attached_clients_list.Flink, net_ebpf_extension_hook_client_t, link);
    RELEASE_PUSH_LOCK_SHARED(&provider_context->lock);
    return client_context;
}

net_ebpf_extension_hook_client_t*
net_ebpf_extension_hook_get_next_attached_client(
    _In_ net_ebpf_extension_hook_provider_t* provider_context,
    _In_opt_ const net_ebpf_extension_hook_client_t* client_context)
{
    net_ebpf_extension_hook_client_t* next_client = NULL;
    ACQUIRE_PUSH_LOCK_SHARED(&provider_context->lock);
    if (client_context == NULL) {
        // Return the first attached client (if any).
        if (!IsListEmpty(&provider_context->attached_clients_list))
            next_client = (net_ebpf_extension_hook_client_t*)CONTAINING_RECORD(
                provider_context->attached_clients_list.Flink, net_ebpf_extension_hook_client_t, link);

    } else {
        // Return the next client, unless this is the last one.
        if (client_context->link.Flink != &provider_context->attached_clients_list) {
            next_client = (net_ebpf_extension_hook_client_t*)CONTAINING_RECORD(
                client_context->link.Flink, net_ebpf_extension_hook_client_t, link);
        }
    }
    RELEASE_PUSH_LOCK_SHARED(&provider_context->lock);
    return next_client;
}