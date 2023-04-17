// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Implementation of eBPF Sample extension hook and program information NPI providers registration and
 * unregistration.
 */

#define INITGUID

#include "ebpf_extension_uuids.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_store_helper.h"
#include "ebpf_structs.h"
#include "sample_ext_helpers.h"
#include "sample_ext_ioctls.h"
#include "sample_ext_program_info.h"

#define SAMPLE_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

#define SAMPLE_PID_TGID_VALUE 9999

// Sample Extension helper function addresses table.
static uint64_t
_sample_get_pid_tgid();
static int64_t
_sample_ebpf_extension_helper_function1(_In_ const sample_program_context_t* context);
static int64_t
_sample_ebpf_extension_find(_In_ const void* buffer, uint32_t size, _In_ const void* find, uint32_t arg_size);
static int64_t
_sample_ebpf_extension_replace(
    _In_ const void* buffer, uint32_t size, int64_t position, _In_ const void* replace, uint32_t arg_size);

static const void* _sample_ebpf_extension_helpers[] = {
    (void*)&_sample_ebpf_extension_helper_function1,
    (void*)&_sample_ebpf_extension_find,
    (void*)&_sample_ebpf_extension_replace};

static const ebpf_helper_function_addresses_t _sample_ebpf_extension_helper_function_address_table = {
    EBPF_COUNT_OF(_sample_ebpf_extension_helpers), (uint64_t*)_sample_ebpf_extension_helpers};

static const void* _sample_global_helpers[] = {(void*)&_sample_get_pid_tgid};

static const ebpf_helper_function_addresses_t _sample_global_helper_function_address_table = {
    EBPF_COUNT_OF(_sample_global_helpers), (uint64_t*)_sample_global_helpers};

static ebpf_program_data_t _sample_ebpf_extension_program_data = {
    &_sample_ebpf_extension_program_info,
    &_sample_ebpf_extension_helper_function_address_table,
    &_sample_global_helper_function_address_table};

static const ebpf_extension_data_t _sample_ebpf_extension_program_info_provider_data = {
    SAMPLE_EBPF_EXTENSION_NPI_PROVIDER_VERSION,
    sizeof(_sample_ebpf_extension_program_data),
    &_sample_ebpf_extension_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _sample_ebpf_extension_program_info_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, {0}};

/**
 * @brief Callback invoked when an eBPF Program Information NPI client attaches.
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
_sample_ebpf_extension_program_info_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch);

/**
 * @brief Callback invoked when a Program Information NPI client detaches.
 *
 * @param[in] client_binding_context Provider module's context for binding with the client.
 * @retval STATUS_SUCCESS The operation succeeded.
 * @retval STATUS_INVALID_PARAMETER One or more parameters are invalid.
 */
static NTSTATUS
_sample_ebpf_extension_program_info_provider_detach_client(_In_ const void* provider_binding_context);

/**
 * @brief Callback invoked after the provider module and a client module have detached from one another.
 *
 * @param[in] provider_binding_context Provider module's context for binding with the client.
 */
static void
_sample_ebpf_extension_program_info_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context);

// Sample eBPF extension Program Information NPI provider characteristics

const NPI_PROVIDER_CHARACTERISTICS _sample_ebpf_extension_program_info_provider_characteristics = {
    0,
    sizeof(NPI_PROVIDER_CHARACTERISTICS),
    _sample_ebpf_extension_program_info_provider_attach_client,
    _sample_ebpf_extension_program_info_provider_detach_client,
    _sample_ebpf_extension_program_info_provider_cleanup_binding_context,
    {0,
     sizeof(NPI_REGISTRATION_INSTANCE),
     &EBPF_PROGRAM_INFO_EXTENSION_IID,
     &_sample_ebpf_extension_program_info_provider_moduleid,
     0,
     &_sample_ebpf_extension_program_info_provider_data},
};

/**
 *  @brief This is the per client binding context for program information
 *         NPI provider.
 */
typedef struct _sample_ebpf_extension_program_info_client
{
    HANDLE nmr_binding_handle;
    GUID client_module_id;
} sample_ebpf_extension_program_info_client_t;

typedef struct _sample_ebpf_extension_program_info_provider
{
    HANDLE nmr_provider_handle;
} sample_ebpf_extension_program_info_provider_t;

static sample_ebpf_extension_program_info_provider_t _sample_ebpf_extension_program_info_provider_context = {0};

//
// Hook Provider.
//

NPI_MODULEID DECLSPEC_SELECTANY _sample_ebpf_extension_hook_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

/**
 * @brief Callback invoked when a eBPF hook NPI client attaches.
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
_sample_ebpf_extension_hook_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch);

/**
 * @brief Callback invoked when a Hook NPI client detaches.
 *
 * @param[in] provider_binding_context Provider module's context for binding with the client.
 * @retval STATUS_SUCCESS The operation succeeded.
 * @retval STATUS_INVALID_PARAMETER One or more parameters are invalid.
 */
static NTSTATUS
_sample_ebpf_extension_hook_provider_detach_client(_In_ const void* provider_binding_context);

/**
 * @brief Callback invoked after the provider module and a client module have detached from one another.
 *
 * @param[in] provider_binding_context Provider module's context for binding with the client.
 */
static void
_sample_ebpf_extension_hook_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context);

// Sample eBPF extension Hook NPI provider characteristics
ebpf_attach_provider_data_t _sample_ebpf_extension_attach_provider_data;

ebpf_extension_data_t _sample_ebpf_extension_hook_provider_data = {
    EBPF_ATTACH_PROVIDER_DATA_VERSION,
    sizeof(_sample_ebpf_extension_attach_provider_data),
    &_sample_ebpf_extension_attach_provider_data};

const NPI_PROVIDER_CHARACTERISTICS _sample_ebpf_extension_hook_provider_characteristics = {
    0,
    sizeof(NPI_PROVIDER_CHARACTERISTICS),
    _sample_ebpf_extension_hook_provider_attach_client,
    _sample_ebpf_extension_hook_provider_detach_client,
    _sample_ebpf_extension_hook_provider_cleanup_binding_context,
    {0,
     sizeof(NPI_REGISTRATION_INSTANCE),
     &EBPF_HOOK_EXTENSION_IID,
     &_sample_ebpf_extension_hook_provider_moduleid,
     0,
     &_sample_ebpf_extension_hook_provider_data},
};

/**
 *  @brief This is the only function in the eBPF hook NPI client dispatch table.
 */
typedef ebpf_result_t (*ebpf_invoke_program_function_t)(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result);

typedef struct _sample_ebpf_extension_hook_provider sample_ebpf_extension_hook_provider_t;
/**
 *  @brief This is the per client binding context for the eBPF Hook
 *         NPI provider.
 */
typedef struct _sample_ebpf_extension_hook_client
{
    HANDLE nmr_binding_handle;
    GUID client_module_id;
    const void* client_binding_context;
    const ebpf_extension_data_t* client_data;
    ebpf_invoke_program_function_t invoke_program;
} sample_ebpf_extension_hook_client_t;

/**
 *  @brief This is the provider context of eBPF Hook NPI provider that
 *         maintains the provider registration state.
 */
typedef struct _sample_ebpf_extension_hook_provider
{
    HANDLE nmr_provider_handle;
    sample_ebpf_extension_hook_client_t* attached_client;
} sample_ebpf_extension_hook_provider_t;

static sample_ebpf_extension_hook_provider_t _sample_ebpf_extension_hook_provider_context = {0};

static NTSTATUS
_sample_ebpf_extension_program_info_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    NTSTATUS status = STATUS_SUCCESS;
    sample_ebpf_extension_program_info_client_t* program_info_client = NULL;

    UNREFERENCED_PARAMETER(provider_context);
    UNREFERENCED_PARAMETER(client_dispatch);
    UNREFERENCED_PARAMETER(client_binding_context);

    if ((provider_binding_context == NULL) || (provider_dispatch == NULL)) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *provider_binding_context = NULL;
    *provider_dispatch = NULL;

    program_info_client = (sample_ebpf_extension_program_info_client_t*)ebpf_allocate(
        sizeof(sample_ebpf_extension_program_info_client_t));

    if (program_info_client == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }

    program_info_client->nmr_binding_handle = nmr_binding_handle;
    program_info_client->client_module_id = client_registration_instance->ModuleId->Guid;

Exit:
    if (NT_SUCCESS(status)) {
        *provider_binding_context = program_info_client;
        program_info_client = NULL;
    } else {
        ebpf_free(program_info_client);
    }
    return status;
}

static NTSTATUS
_sample_ebpf_extension_program_info_provider_detach_client(_In_ const void* provider_binding_context)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(provider_binding_context);

    return status;
}

static void
_sample_ebpf_extension_program_info_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context)
{
    ebpf_free(provider_binding_context);
}

void
sample_ebpf_extension_program_info_provider_unregister()
{
    sample_ebpf_extension_program_info_provider_t* provider_context =
        &_sample_ebpf_extension_program_info_provider_context;
    NTSTATUS status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
    if (status == STATUS_PENDING) {
        NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
    }
}

static NTSTATUS
_sample_ebpf_extension_update_store_entries()
{
    NTSTATUS status;

    // Update section information.
    ebpf_program_section_info_t section_info = {
        L"sample_ext",
        (GUID*)&EBPF_PROGRAM_TYPE_SAMPLE,
        (GUID*)&EBPF_ATTACH_TYPE_SAMPLE,
        BPF_PROG_TYPE_SAMPLE,
        BPF_ATTACH_TYPE_SAMPLE};
    status = _ebpf_store_update_section_information(&section_info, 1);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Update program information
    ebpf_extension_data_t* extension_data;
    ebpf_program_data_t* program_data;
    extension_data = (ebpf_extension_data_t*)_sample_ebpf_extension_program_info_provider_characteristics
                         .ProviderRegistrationInstance.NpiSpecificCharacteristics;
    program_data = (ebpf_program_data_t*)extension_data->data;

    status = _ebpf_store_update_program_information(program_data->program_info, 1);

    return status;
}

NTSTATUS
sample_ebpf_extension_program_info_provider_register()
{
    sample_ebpf_extension_program_info_provider_t* local_provider_context;
    ebpf_extension_data_t* extension_data;
    ebpf_program_data_t* program_data;

    NTSTATUS status = STATUS_SUCCESS;

    status = _sample_ebpf_extension_update_store_entries();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    extension_data = (ebpf_extension_data_t*)_sample_ebpf_extension_program_info_provider_characteristics
                         .ProviderRegistrationInstance.NpiSpecificCharacteristics;
    program_data = (ebpf_program_data_t*)extension_data->data;
    _sample_ebpf_extension_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_SAMPLE;

    local_provider_context = &_sample_ebpf_extension_program_info_provider_context;

    status = NmrRegisterProvider(
        &_sample_ebpf_extension_program_info_provider_characteristics,
        local_provider_context,
        &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        sample_ebpf_extension_program_info_provider_unregister();
    }

    return status;
}

//
// Hook Provider.
//

static NTSTATUS
_sample_ebpf_extension_hook_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    NTSTATUS status = STATUS_SUCCESS;
    sample_ebpf_extension_hook_provider_t* local_provider_context =
        (sample_ebpf_extension_hook_provider_t*)provider_context;
    sample_ebpf_extension_hook_client_t* hook_client = NULL;
    ebpf_extension_dispatch_table_t* client_dispatch_table;

    if ((provider_binding_context == NULL) || (provider_dispatch == NULL) || (local_provider_context == NULL)) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (local_provider_context->attached_client != NULL) {
        // Currently only a single client is allowed to attach.
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *provider_binding_context = NULL;
    *provider_dispatch = NULL;

    hook_client = (sample_ebpf_extension_hook_client_t*)ebpf_allocate(sizeof(sample_ebpf_extension_hook_client_t));

    if (hook_client == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }

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

    local_provider_context->attached_client = hook_client;

Exit:

    if (NT_SUCCESS(status)) {
        *provider_binding_context = hook_client;
        hook_client = NULL;
    } else {
        ebpf_free(hook_client);
    }

    return status;
}

static NTSTATUS
_sample_ebpf_extension_hook_provider_detach_client(_In_ const void* provider_binding_context)
{
    NTSTATUS status = STATUS_SUCCESS;

    sample_ebpf_extension_hook_client_t* local_client_context =
        (sample_ebpf_extension_hook_client_t*)provider_binding_context;
    sample_ebpf_extension_hook_provider_t* provider_context = NULL;

    if (local_client_context == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    provider_context = &_sample_ebpf_extension_hook_provider_context;
    provider_context->attached_client = NULL;

Exit:
    return status;
}

static void
_sample_ebpf_extension_hook_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context)
{
    ebpf_free(provider_binding_context);
}

void
sample_ebpf_extension_hook_provider_unregister()
{
    sample_ebpf_extension_hook_provider_t* provider_context = &_sample_ebpf_extension_hook_provider_context;

    NTSTATUS status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
    if (status == STATUS_PENDING) {
        // Wait for clients to detach.
        NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
    }
}

NTSTATUS
sample_ebpf_extension_hook_provider_register()
{
    sample_ebpf_extension_hook_provider_t* local_provider_context;
    NTSTATUS status = STATUS_SUCCESS;

    _sample_ebpf_extension_attach_provider_data.supported_program_type = EBPF_PROGRAM_TYPE_SAMPLE;
    _sample_ebpf_extension_attach_provider_data.bpf_attach_type = BPF_ATTACH_TYPE_SAMPLE;
    _sample_ebpf_extension_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_SAMPLE;

    local_provider_context = &_sample_ebpf_extension_hook_provider_context;

    status = NmrRegisterProvider(
        &_sample_ebpf_extension_hook_provider_characteristics,
        local_provider_context,
        &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        sample_ebpf_extension_hook_provider_unregister();
    }

    return status;
}

_Must_inspect_result_ ebpf_result_t
sample_ebpf_extension_invoke_program(_In_ const sample_program_context_t* context, _Out_ uint32_t* result)
{
    ebpf_result_t return_value = EBPF_SUCCESS;

    sample_ebpf_extension_hook_provider_t* hook_provider_context = &_sample_ebpf_extension_hook_provider_context;

    sample_ebpf_extension_hook_client_t* hook_client = hook_provider_context->attached_client;

    if (hook_client == NULL) {
        return_value = EBPF_FAILED;
        goto Exit;
    }
    ebpf_invoke_program_function_t invoke_program = hook_client->invoke_program;
    const void* client_binding_context = hook_client->client_binding_context;

    // Run the eBPF program using cached copies of invoke_program and client_binding_context.
    return_value = invoke_program(client_binding_context, context, result);

Exit:
    return return_value;
}

_Must_inspect_result_ ebpf_result_t
sample_ebpf_extension_profile_program(
    _Inout_ sample_ebpf_ext_profile_request_t* request,
    size_t request_length,
    _Inout_ sample_ebpf_ext_profile_reply_t* reply)
{
    ebpf_result_t return_value = EBPF_SUCCESS;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    uint32_t result;
    KIRQL old_irql = PASSIVE_LEVEL;
    sample_program_context_t program_context = {
        request->data, request->data + request_length - FIELD_OFFSET(sample_ebpf_ext_profile_request_t, data)};

    sample_ebpf_extension_hook_provider_t* hook_provider_context = &_sample_ebpf_extension_hook_provider_context;

    sample_ebpf_extension_hook_client_t* hook_client = hook_provider_context->attached_client;

    if (hook_client == NULL) {
        return_value = EBPF_FAILED;
        goto Exit;
    }
    ebpf_invoke_program_function_t invoke_program = hook_client->invoke_program;
    const void* client_binding_context = hook_client->client_binding_context;

    program_context.uint32_data = KeGetCurrentProcessorNumber();

    KeQueryPerformanceCounter(&start);
    if (request->flags & SAMPLE_EBPF_EXT_FLAG_DISPATCH) {
        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
    }
    for (size_t i = 0; i < request->iterations; i++) {
        invoke_program(client_binding_context, &program_context, &result);
    }
    if (request->flags & SAMPLE_EBPF_EXT_FLAG_DISPATCH) {
        KeLowerIrql(old_irql);
    }
    KeQueryPerformanceCounter(&end);

    reply->duration = end.QuadPart - start.QuadPart;

Exit:
    return return_value;
}

// Global Helper Function Definitions.
static uint64_t
_sample_get_pid_tgid()
{
    return SAMPLE_PID_TGID_VALUE;
}

// Helper Function Definitions.

static int64_t
_sample_ebpf_extension_helper_function1(_In_ const sample_program_context_t* context)
{
    UNREFERENCED_PARAMETER(context);
    return 0;
}

static int64_t
_sample_ebpf_extension_find(_In_ const void* buffer, uint32_t size, _In_ const void* find, uint32_t arg_size)
{
    UNREFERENCED_PARAMETER(size);
    UNREFERENCED_PARAMETER(arg_size);
    return strstr((char*)buffer, (char*)find) - (char*)buffer;
}

static int64_t
_sample_ebpf_extension_replace(
    _In_ const void* buffer, uint32_t size, int64_t position, _In_ const void* replace, uint32_t arg_size)
{
    int64_t result = 0;
    char* dest;
    char* end = (char*)buffer + size - 1;
    char* source = (char*)replace;
    UNREFERENCED_PARAMETER(arg_size);

    if (position < 0) {
        result = -1;
        goto Exit;
    }

    if (position >= size) {
        result = -1;
        goto Exit;
    }

    dest = (char*)buffer + position;
    while (dest != end) {
        if (*source == '\0') {
            break;
        }
        *dest++ = *source++;
    }

Exit:
    return result;
}
