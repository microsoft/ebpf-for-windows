// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "net_ebpf_ext_hook_provider.h"

/**
 *  @brief This is the only function in the eBPF hook NPI client dispatch table.
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

typedef struct _net_ebpf_extension_hook_client
{
    HANDLE nmr_binding_handle;
    GUID client_module_id;
    const void* client_binding_context;
    const ebpf_extension_data_t* client_data;
    ebpf_invoke_program_function_t invoke_program;
    struct _net_ebpf_extension_hook_provider* provider_context;
    net_ebpf_extension_hook_execution_t execution_type;
    PIO_WORKITEM detach_work_item;
    net_ebpf_ext_hook_client_rundown_t rundown;
} net_ebpf_extension_hook_client_t;

typedef struct _net_ebpf_extension_hook_provider
{
    HANDLE nmr_provider_handle;
    net_ebpf_extension_hook_execution_t execution_type;
    net_ebpf_extension_hook_client_t* attached_client;
} net_ebpf_extension_hook_provider_t;

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
        ExAcquirePushLockExclusive(&rundown->passive.lock);
        ExReleasePushLockExclusive(&rundown->passive.lock);
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
    ExFreePool(hook_client);
}

_Acquires_lock_(hook_client) bool net_ebpf_extension_attach_enter_rundown(
    _Inout_ net_ebpf_extension_hook_client_t* hook_client, net_ebpf_extension_hook_execution_t execution_type)
{
    net_ebpf_ext_hook_client_rundown_t* rundown = &hook_client->rundown;
    if (execution_type == EXECUTION_PASSIVE) {
        ExAcquirePushLockShared(&rundown->passive.lock);
    }

    return (rundown->rundown_occurred == FALSE);
}

_Releases_lock_(hook_client) void net_ebpf_extension_attach_leave_rundown(
    _Inout_ net_ebpf_extension_hook_client_t* hook_client, net_ebpf_extension_hook_execution_t execution_type)
{
    net_ebpf_ext_hook_client_rundown_t* rundown = &hook_client->rundown;
    if (execution_type == EXECUTION_PASSIVE) {
        _Analysis_assume_lock_held_(&rundown->passive.lock);
        ExReleasePushLockShared(&rundown->passive.lock);
    }
}

const ebpf_extension_data_t*
net_ebpf_extension_get_client_data(_In_ const net_ebpf_extension_hook_client_t* hook_client)
{
    return hook_client->client_data;
}

ebpf_result_t
net_ebpf_extension_hook_invoke_program(
    _In_ const net_ebpf_extension_hook_client_t* client, _In_ void* context, _Out_ uint32_t* result)
{
    ebpf_invoke_program_function_t invoke_program = client->invoke_program;
    const void* client_binding_context = client->client_binding_context;

    return invoke_program(client_binding_context, context, result);
}

NTSTATUS
net_ebpf_extension_hook_provider_attach_client(
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
    // The following line can cause a leak if the provider has already an attached client.
    // This will be fixed as part of issue #754.
    local_provider_context->attached_client = hook_client;

    status = _ebpf_ext_attach_init_rundown(hook_client);
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

NTSTATUS
net_ebpf_extension_hook_provider_detach_client(_In_ void* provider_binding_context)
{
    NTSTATUS status = STATUS_PENDING;

    net_ebpf_extension_hook_client_t* local_client_context =
        (net_ebpf_extension_hook_client_t*)provider_binding_context;
    net_ebpf_extension_hook_provider_t* provider_context = NULL;

    if (local_client_context == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    provider_context = local_client_context->provider_context;
    provider_context->attached_client = NULL;

    IoQueueWorkItem(
        local_client_context->detach_work_item,
        _net_ebpf_extension_detach_client_completion,
        DelayedWorkQueue,
        (PVOID)local_client_context);

Exit:
    return status;
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
    _In_ const NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    net_ebpf_extension_hook_execution_t execution_type,
    _Outptr_ net_ebpf_extension_hook_provider_t** provider_context)
{
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_hook_provider_t* local_provider_context = NULL;

    local_provider_context = (net_ebpf_extension_hook_provider_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_hook_provider_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (local_provider_context == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }
    memset(local_provider_context, 0, sizeof(net_ebpf_extension_hook_provider_t));

    local_provider_context->execution_type = execution_type;
    status = NmrRegisterProvider(
        provider_characteristics, local_provider_context, &local_provider_context->nmr_provider_handle);
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
net_ebpf_extension_get_attached_client(_In_ const net_ebpf_extension_hook_provider_t* provider_context)
{
    return provider_context->attached_client;
}