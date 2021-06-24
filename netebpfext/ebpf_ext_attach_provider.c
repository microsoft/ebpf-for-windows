// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_ext_attach_provider.h"

typedef ebpf_result_t (*ebpf_ext_attach_hook_function_t)(
    _In_ void* bind_context, _In_ void* context, _Out_ uint32_t* result);

typedef struct _ebpf_ext_attach_hook_provider_registration
{
    ebpf_extension_data_t* provider_data;
    ebpf_extension_provider_t* provider;
    GUID client_id;
    volatile void* client_binding_context;
    const ebpf_extension_data_t* client_data;
    volatile ebpf_ext_attach_hook_function_t invoke_hook;
    ebpf_ext_hook_execution_t execution_type;
    union
    {
        struct
        {
            KDPC rundown_dpc;
            KEVENT rundown_wait;
        } dispatch;
        struct
        {
            EX_PUSH_LOCK lock;
        } passive;
    };
} ebpf_ext_attach_hook_provider_registration_t;

/**
 * @brief Callback invoked when a client (an eBPF program) attaches.
 *
 * @param[in] context Pointer to the ebpf_ext_attach_hook_provider_registration_t.
 * @param[in] client_id GUID identifying a eBPF program.
 * @param[in] client_binding_context Context used when invoking the hook.
 * @param[in] client_data Data about the client.
 * @param[in] client_dispatch_table Function table containing function pointer
 * to invoke eBPF program.
 * @retval EBPF_SUCCESS The operation succeeded.
 * @retval EBPF_EXTENSION_FAILED_TO_LOAD A client is already attached.
 */
static ebpf_result_t
_ebpf_ext_attach_provider_client_attach_callback(
    _In_ void* context,
    _In_ const GUID* client_id,
    _In_ void* client_binding_context,
    _In_ const ebpf_extension_data_t* client_data,
    _In_ const ebpf_extension_dispatch_table_t* client_dispatch_table)
{
    ebpf_ext_attach_hook_provider_registration_t* hook_registration =
        (ebpf_ext_attach_hook_provider_registration_t*)context;
    if (hook_registration->client_binding_context)
        return EBPF_EXTENSION_FAILED_TO_LOAD;

    hook_registration->client_id = *client_id;
    hook_registration->client_data = client_data;
    hook_registration->invoke_hook = (ebpf_ext_attach_hook_function_t)client_dispatch_table->function[0];

    hook_registration->client_binding_context = client_binding_context;

    // After invoke_hook and client_binding_context are set, the eBPF program
    // may be invoked.

    return EBPF_SUCCESS;
}

static _Function_class_(KDEFERRED_ROUTINE) _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_requires_min_(DISPATCH_LEVEL)
    _IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ void _ebpf_ext_attach_rundown(
        _In_ KDPC* dpc,
        _In_opt_ void* deferred_context,
        _In_opt_ void* system_argument_1,
        _In_opt_ void* system_argument_2)
{
    ebpf_ext_attach_hook_provider_registration_t* registration =
        (ebpf_ext_attach_hook_provider_registration_t*)deferred_context;

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(system_argument_1);
    UNREFERENCED_PARAMETER(system_argument_2);
    if (registration)
        KeSetEvent(&registration->dispatch.rundown_wait, 0, FALSE);
}

/**
 * @brief Initialize the rundown state in
 * ebpf_ext_attach_hook_provider_registration_t.
 *
 * @param registration Registration object to initialize.
 * @param execution_type Type of rundown support required.
 */
static void
_ebpf_ext_attach_init_rundown(
    _In_ ebpf_ext_attach_hook_provider_registration_t* registration, ebpf_ext_hook_execution_t execution_type)
{
    registration->execution_type = execution_type;
    if (registration->execution_type == EBPF_EXT_HOOK_EXECUTION_PASSIVE) {
        ExInitializePushLock(&registration->passive.lock);
    } else {
        KeInitializeEvent(&(registration->dispatch.rundown_wait), SynchronizationEvent, FALSE);
        KeInitializeDpc(&(registration->dispatch.rundown_dpc), _ebpf_ext_attach_rundown, registration);
    }
}

/**
 * @brief Block execution of the thread until all invocations are completed.
 *
 * @param registration Registration object to wait for.
 */
static void
_ebpf_ext_attach_wait_for_rundown(_In_ ebpf_ext_attach_hook_provider_registration_t* registration)
{
    if (registration->execution_type == EBPF_EXT_HOOK_EXECUTION_PASSIVE) {
        ExAcquirePushLockExclusive(&registration->passive.lock);
        ExReleasePushLockExclusive(&registration->passive.lock);
    } else {
        // Queue a DPC to each CPU and wait for it to run.
        // After it has run on each CPU we can be sure that no
        // DPC is busy processing a hook.
        uint32_t maximum_processor = KeQueryMaximumProcessorCount();
        uint32_t processor;
        for (processor = 0; processor < maximum_processor; processor++) {
            KeSetTargetProcessorDpc(&registration->dispatch.rundown_dpc, (uint8_t)processor);
            if (KeInsertQueueDpc(&registration->dispatch.rundown_dpc, NULL, NULL)) {
                KeWaitForSingleObject(&registration->dispatch.rundown_wait, Executive, KernelMode, FALSE, NULL);
            }
        }
    }
}

/**
 * @brief Callback invoked when a client detaches. The client eBPF program
 * remains valid until this callback returns.
 *
 * @param context The ebpf_ext_attach_hook_provider_registration_t.
 * @param client_id Identity of the eBPF program detaching.
 * @retval EBPF_SUCCESS The operation succeeded.
 */
static ebpf_result_t
_ebpf_ext_attach_provider_client_detach_callback(_In_ void* context, _In_ const GUID* client_id)
{
    ebpf_ext_attach_hook_provider_registration_t* hook_registration =
        (ebpf_ext_attach_hook_provider_registration_t*)context;
    UNREFERENCED_PARAMETER(client_id);

    // Prevent new callbacks from starting by setting client_binding_context and
    // invoke_hook to NULL.
    hook_registration->client_binding_context = NULL;
    hook_registration->client_data = NULL;
    hook_registration->invoke_hook = NULL;

    // TODO: Issue https://github.com/microsoft/ebpf-for-windows/issues/270
    // Client detach should return pending and then callback once invocations
    // complete.

    // Wait for any in progress callbacks to complete.
    _ebpf_ext_attach_wait_for_rundown(hook_registration);

    // At this point, no new invocations of the eBPF program will occur.

    // Permit the EC to finish unloading the eBPF program.
    return EBPF_SUCCESS;
}

bool
ebpf_ext_attach_enter_rundown(_In_ ebpf_ext_attach_hook_provider_registration_t* registration)
{
    if (registration->execution_type == EBPF_EXT_HOOK_EXECUTION_PASSIVE) {
        ExAcquirePushLockShared(&registration->passive.lock);
    }

    return (registration->client_binding_context != NULL);
}

void
ebpf_ext_attach_leave_rundown(_In_ ebpf_ext_attach_hook_provider_registration_t* registration)
{
    if (registration->execution_type == EBPF_EXT_HOOK_EXECUTION_PASSIVE) {
        ExReleasePushLockShared(&registration->passive.lock);
    }
}

ebpf_result_t
ebpf_ext_attach_register_provider(
    _In_ const ebpf_attach_type_t* attach_type,
    ebpf_ext_hook_execution_t execution_type,
    _Outptr_ ebpf_ext_attach_hook_provider_registration_t** registration)
{
    ebpf_result_t return_value;
    ebpf_ext_attach_hook_provider_registration_t* local_registration = NULL;

    local_registration = ebpf_allocate(sizeof(ebpf_ext_attach_hook_provider_registration_t));
    if (!local_registration) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(local_registration, 0, sizeof(ebpf_ext_attach_hook_provider_registration_t));

    _ebpf_ext_attach_init_rundown(local_registration, execution_type);

    return_value = ebpf_provider_load(
        &local_registration->provider,
        attach_type,
        local_registration,
        local_registration->provider_data,
        NULL,
        local_registration,
        _ebpf_ext_attach_provider_client_attach_callback,
        _ebpf_ext_attach_provider_client_detach_callback);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    *registration = local_registration;
    local_registration = NULL;

Done:
    ebpf_ext_attach_unregister_provider(local_registration);

    return return_value;
}

void
ebpf_ext_attach_unregister_provider(_In_opt_ _Post_invalid_ __drv_freesMem(Mem)
                                        ebpf_ext_attach_hook_provider_registration_t* registration)
{
    if (registration) {
        ebpf_provider_unload(registration->provider);
    }
    ebpf_free(registration);
}

ebpf_result_t
ebpf_ext_attach_invoke_hook(
    _In_ ebpf_ext_attach_hook_provider_registration_t* registration, _In_ void* context, _Out_ uint32_t* result)
{
    // Note:
    // Capture local copies of invoke_hook and client_binding_context.
    ebpf_ext_attach_hook_function_t invoke_hook = (ebpf_ext_attach_hook_function_t)registration->invoke_hook;
    void* client_binding_context = (void*)registration->client_binding_context;

    // If either are NULL, then the client has detached already.
    if (!invoke_hook || !client_binding_context) {
        *result = 0;
        return EBPF_SUCCESS;
    }

    // Run the eBPF program using cached copies of invoke_hook and client_binding_context.
    return invoke_hook(client_binding_context, context, result);
}