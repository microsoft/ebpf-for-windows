// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @brief Implementation of eBPF Sample extension hook and program information NPI providers registration and
 * unregistration.
 */

#define INITGUID

#define SAMPLE_EXT_POOL_TAG_DEFAULT 'lpms'
unsigned int map_pool_tag = SAMPLE_EXT_POOL_TAG_DEFAULT;

#include "cxplat.h"
#include "ebpf_extension.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"
#include "sample_ext.h"
#include "sample_ext_ioctls.h"
#include "sample_ext_maps.h"
#include "sample_ext_program_info.h"

#include <netioddk.h>
#include <ntstatus.h>

#define SAMPLE_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

#define SAMPLE_PID_TGID_VALUE 9999

#define CXPLAT_FREE(x) cxplat_free(x, CXPLAT_POOL_FLAG_NON_PAGED, SAMPLE_EXT_POOL_TAG_DEFAULT)

#define MAP_TYPE(map) (((sample_core_map_t*)(map))->map_type)

// Define the sample map type
#define BPF_MAP_TYPE_SAMPLE_ARRAY_MAP 0xF000
#define BPF_MAP_TYPE_SAMPLE_HASH_MAP 0xF001

NPI_MODULEID DECLSPEC_SELECTANY _sample_ebpf_extension_map_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, EBPF_SAMPLE_MAP_PROVIDER_GUID};

static uint64_t _map_context_offset = 0;

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
static int64_t
_sample_ebpf_extension_helper_implicit_1(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const sample_program_context_t* context);
static int64_t
_sample_ebpf_extension_helper_implicit_2(
    uint32_t arg,
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    _In_ const sample_program_context_t* context);

static void*
_sample_ext_helper_map_lookup_element(
    _In_ const void* map, _In_ const uint8_t* key, uint64_t dummy_param1, uint64_t dummy_param2, uint64_t dummy_param3);

static const void* _sample_ebpf_extension_helpers[] = {
    (void*)&_sample_ebpf_extension_helper_function1,
    (void*)&_sample_ebpf_extension_find,
    (void*)&_sample_ebpf_extension_replace,
    (void*)&_sample_ebpf_extension_helper_implicit_1,
    (void*)&_sample_ebpf_extension_helper_implicit_2,
    (void*)&_sample_ext_helper_map_lookup_element};

static const ebpf_helper_function_addresses_t _sample_ebpf_extension_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_sample_ebpf_extension_helpers),
    (uint64_t*)_sample_ebpf_extension_helpers};

static const void* _sample_global_helpers[] = {(void*)&_sample_get_pid_tgid};

static const ebpf_helper_function_addresses_t _sample_global_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER, EBPF_COUNT_OF(_sample_global_helpers), (uint64_t*)_sample_global_helpers};

//
// Sample Map Provider Implementation
//
typedef struct _sample_hash_map
{
    sample_base_hash_map_t base;
    ebpf_map_client_dispatch_table_t* client_dispatch;
} sample_hash_map_t;

typedef struct _sample_array_map
{
    sample_base_array_map_t base;
    ebpf_map_client_dispatch_table_t* client_dispatch;
} sample_array_map_t;

// Map provider function declarations
static ebpf_result_t
_sample_map_create(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Outptr_ void** map_context);

static void
_sample_map_delete(_In_ _Post_invalid_ void* map);

static ebpf_result_t
_sample_map_find_entry(
    _In_ void* map,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    _Outptr_ uint8_t** value,
    uint32_t flags);

static ebpf_result_t
_sample_map_update_entry(
    _In_ void* map,
    size_t key_size,
    _In_opt_ const uint8_t* key,
    size_t value_size,
    _In_opt_ const uint8_t* value,
    ebpf_map_option_t option,
    uint32_t flags);

static ebpf_result_t
_sample_map_delete_entry(_In_ void* map, size_t key_size, _In_reads_opt_(key_size) const uint8_t* key, uint32_t flags);

static ebpf_result_t
_sample_map_get_next_key_and_value(
    _In_ void* map,
    size_t key_size,
    _In_ const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value);

static ebpf_result_t
_sample_map_associate_program(_In_ const void* map_context, _In_ const ebpf_program_type_t* program_type);

// static uint32_t _sample_supported_map_types[2] = {BPF_MAP_TYPE_SAMPLE_ARRAY_MAP, BPF_MAP_TYPE_SAMPLE_HASH_MAP};

// Sample map extension data
static ebpf_map_provider_dispatch_table_t _sample_map_dispatch_table = {
    EBPF_MAP_PROVIDER_DISPATCH_TABLE_HEADER,
    .create_map_function = _sample_map_create,
    .delete_map_function = _sample_map_delete,
    .find_element_function = _sample_map_find_entry,
    .update_element_function = _sample_map_update_entry,
    .delete_element_function = _sample_map_delete_entry,
    .get_next_key_and_value_function = _sample_map_get_next_key_and_value,
    .associate_program_function = _sample_map_associate_program};

static ebpf_map_provider_data_t _sample_array_map_provider_data = {
    EBPF_MAP_PROVIDER_DATA_HEADER, BPF_MAP_TYPE_SAMPLE_ARRAY_MAP, &_sample_map_dispatch_table};

static ebpf_map_provider_data_t _sample_hash_map_provider_data = {
    EBPF_MAP_PROVIDER_DATA_HEADER, BPF_MAP_TYPE_SAMPLE_HASH_MAP, &_sample_map_dispatch_table};

// Map provider context structure
typedef struct _sample_ebpf_extension_map_provider
{
    HANDLE nmr_provider_handle;
} sample_ebpf_extension_map_provider_t;

static sample_ebpf_extension_map_provider_t _sample_ebpf_extension_array_map_provider_context = {NULL};
static sample_ebpf_extension_map_provider_t _sample_ebpf_extension_hash_map_provider_context = {NULL};

typedef struct _sample_extension_map_provider_binding_context
{
    ebpf_map_client_dispatch_table_t client_dispatch_table;
} sample_extension_map_provider_binding_context_t;

// Forward declarations for map provider
static NTSTATUS
_sample_ebpf_extension_map_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch);

static NTSTATUS
_sample_ebpf_extension_map_provider_detach_client(_In_ const void* provider_binding_context);

static void
_sample_ebpf_extension_map_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context);

// Map provider characteristics
static const NPI_PROVIDER_CHARACTERISTICS _sample_ebpf_extension_array_map_provider_characteristics = {
    0,                                    // Version
    sizeof(NPI_PROVIDER_CHARACTERISTICS), // Length
    _sample_ebpf_extension_map_provider_attach_client,
    _sample_ebpf_extension_map_provider_detach_client,
    _sample_ebpf_extension_map_provider_cleanup_binding_context,
    {
        0,                                 // Version
        sizeof(NPI_REGISTRATION_INSTANCE), // Length
        &EBPF_MAP_INFO_EXTENSION_IID,
        &_sample_ebpf_extension_map_provider_moduleid, // Module ID.
        0,                                             // Number
        &_sample_array_map_provider_data               // Module context (extension data)
    }};

static const NPI_PROVIDER_CHARACTERISTICS _sample_ebpf_extension_hash_map_provider_characteristics = {
    0,                                    // Version
    sizeof(NPI_PROVIDER_CHARACTERISTICS), // Length
    _sample_ebpf_extension_map_provider_attach_client,
    _sample_ebpf_extension_map_provider_detach_client,
    _sample_ebpf_extension_map_provider_cleanup_binding_context,
    {
        0,                                 // Version
        sizeof(NPI_REGISTRATION_INSTANCE), // Length
        &EBPF_MAP_INFO_EXTENSION_IID,
        &_sample_ebpf_extension_map_provider_moduleid, // Module ID.
        0,                                             // Number
        &_sample_hash_map_provider_data                // Module context (extension data)
    }};

static ebpf_result_t
_sample_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_sample_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

static ebpf_program_data_t _sample_ebpf_extension_program_data = {
    EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_sample_ebpf_extension_program_info,
    .program_type_specific_helper_function_addresses = &_sample_ebpf_extension_helper_function_address_table,
    .global_helper_function_addresses = &_sample_global_helper_function_address_table,
    .context_create = &_sample_context_create,
    .context_destroy = &_sample_context_destroy,
    DISPATCH_LEVEL,
    {0}};

NPI_MODULEID DECLSPEC_SELECTANY _sample_ebpf_extension_program_info_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, EBPF_PROGRAM_TYPE_SAMPLE_GUID};

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
     &_sample_ebpf_extension_program_data},
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

NPI_MODULEID DECLSPEC_SELECTANY _sample_ebpf_extension_hook_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, EBPF_ATTACH_TYPE_SAMPLE_GUID};

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
ebpf_attach_provider_data_t _sample_ebpf_extension_attach_provider_data = {
    EBPF_ATTACH_PROVIDER_DATA_HEADER, EBPF_PROGRAM_TYPE_SAMPLE_GUID, BPF_ATTACH_TYPE_SAMPLE, BPF_LINK_TYPE_UNSPEC};

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
     &_sample_ebpf_extension_attach_provider_data},
};

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
    ebpf_program_invoke_function_t invoke_program;
    ebpf_program_batch_begin_invoke_function_t begin_batch_program_invoke;
    ebpf_program_batch_end_invoke_function_t end_batch_program_invoke;
    ebpf_program_batch_invoke_function_t batch_program_invoke;
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

    program_info_client = cxplat_allocate(
        CXPLAT_POOL_FLAG_NON_PAGED, sizeof(sample_ebpf_extension_program_info_client_t), SAMPLE_EXT_POOL_TAG_DEFAULT);
    if (program_info_client == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }

    RtlZeroMemory(program_info_client, sizeof(sample_ebpf_extension_program_info_client_t));

    program_info_client->nmr_binding_handle = nmr_binding_handle;
    program_info_client->client_module_id = client_registration_instance->ModuleId->Guid;

Exit:
    if (NT_SUCCESS(status)) {
        *provider_binding_context = program_info_client;
        program_info_client = NULL;
    } else if (program_info_client != NULL) {
        CXPLAT_FREE(program_info_client);
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
    CXPLAT_FREE(provider_binding_context);
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

NTSTATUS
sample_ebpf_extension_program_info_provider_register()
{
    sample_ebpf_extension_program_info_provider_t* local_provider_context;
    NTSTATUS status = STATUS_SUCCESS;

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
    ebpf_extension_program_dispatch_table_t* client_dispatch_table;

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

    hook_client = cxplat_allocate(
        CXPLAT_POOL_FLAG_NON_PAGED, sizeof(sample_ebpf_extension_hook_client_t), SAMPLE_EXT_POOL_TAG_DEFAULT);
    if (hook_client == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }

    RtlZeroMemory(hook_client, sizeof(sample_ebpf_extension_hook_client_t));

    if (hook_client == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }

    hook_client->nmr_binding_handle = nmr_binding_handle;
    hook_client->client_module_id = client_registration_instance->ModuleId->Guid;
    hook_client->client_binding_context = client_binding_context;
    hook_client->client_data = client_registration_instance->NpiSpecificCharacteristics;
    client_dispatch_table = (ebpf_extension_program_dispatch_table_t*)client_dispatch;
    if (client_dispatch_table == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    hook_client->invoke_program = client_dispatch_table->ebpf_program_invoke_function;
    hook_client->batch_program_invoke = client_dispatch_table->ebpf_program_batch_invoke_function;
    hook_client->begin_batch_program_invoke = client_dispatch_table->ebpf_program_batch_begin_invoke_function;
    hook_client->end_batch_program_invoke = client_dispatch_table->ebpf_program_batch_end_invoke_function;

    local_provider_context->attached_client = hook_client;

Exit:

    if (NT_SUCCESS(status)) {
        *provider_binding_context = hook_client;
        hook_client = NULL;
    } else if (hook_client != NULL) {
        CXPLAT_FREE(hook_client);
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
    CXPLAT_FREE(provider_binding_context);
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

bool
_sample_validate_client_map_data(_In_ const ebpf_map_client_data_t* client_data)
{
    if (client_data->header.version != EBPF_MAP_CLIENT_DATA_CURRENT_VERSION &&
        client_data->header.size != EBPF_MAP_CLIENT_DATA_CURRENT_VERSION_SIZE) {
        return false;
    }
    return true;
}

//
// Map Provider Registration
//

static NTSTATUS
_sample_ebpf_extension_map_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    UNREFERENCED_PARAMETER(nmr_binding_handle);
    UNREFERENCED_PARAMETER(client_registration_instance);
    UNREFERENCED_PARAMETER(client_binding_context);
    UNREFERENCED_PARAMETER(client_dispatch);
    UNREFERENCED_PARAMETER(provider_context);

    sample_extension_map_provider_binding_context_t* local_provider_context = cxplat_allocate(
        CXPLAT_POOL_FLAG_NON_PAGED,
        sizeof(sample_extension_map_provider_binding_context_t),
        SAMPLE_EXT_POOL_TAG_DEFAULT);
    if (local_provider_context == NULL) {
        return STATUS_NO_MEMORY;
    }

    const ebpf_map_client_data_t* client_data =
        (const ebpf_map_client_data_t*)client_registration_instance->NpiSpecificCharacteristics;
    if (!_sample_validate_client_map_data(client_data)) {
        CXPLAT_FREE(local_provider_context);
        return STATUS_INVALID_PARAMETER;
    }

    memcpy(
        &local_provider_context->client_dispatch_table,
        client_data->dispatch_table,
        min(sizeof(ebpf_map_client_dispatch_table_t), client_data->dispatch_table->header.total_size));

    // As per contract, map context offset is same for all the map instances created by the client.
    // Save it in a global variable.
    WriteULong64NoFence((volatile uint64_t*)&_map_context_offset, client_data->map_context_offset);

    *provider_binding_context = local_provider_context;
    *provider_dispatch = NULL;

    return STATUS_SUCCESS;
}

static NTSTATUS
_sample_ebpf_extension_map_provider_detach_client(_In_ const void* provider_binding_context)
{
    UNREFERENCED_PARAMETER(provider_binding_context);
    return STATUS_SUCCESS;
}

static void
_sample_ebpf_extension_map_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context)
{
    sample_extension_map_provider_binding_context_t* local_provider_context =
        (sample_extension_map_provider_binding_context_t*)provider_binding_context;
    CXPLAT_FREE(local_provider_context);
}

void
sample_ebpf_extension_map_provider_unregister()
{
    NTSTATUS status;

    if (_sample_ebpf_extension_array_map_provider_context.nmr_provider_handle != NULL) {
        status = NmrDeregisterProvider(_sample_ebpf_extension_array_map_provider_context.nmr_provider_handle);
        if (status == STATUS_PENDING) {
            // Wait for clients to detach.
            NmrWaitForProviderDeregisterComplete(_sample_ebpf_extension_array_map_provider_context.nmr_provider_handle);
        }
        _sample_ebpf_extension_array_map_provider_context.nmr_provider_handle = NULL;
    }

    if (_sample_ebpf_extension_hash_map_provider_context.nmr_provider_handle != NULL) {
        status = NmrDeregisterProvider(_sample_ebpf_extension_hash_map_provider_context.nmr_provider_handle);
        if (status == STATUS_PENDING) {
            // Wait for clients to detach.
            NmrWaitForProviderDeregisterComplete(_sample_ebpf_extension_hash_map_provider_context.nmr_provider_handle);
        }
        _sample_ebpf_extension_hash_map_provider_context.nmr_provider_handle = NULL;
    }
}

NTSTATUS
sample_ebpf_extension_map_provider_register()
{
    sample_ebpf_extension_map_provider_t* local_provider_context;
    NTSTATUS status = STATUS_SUCCESS;

    // Register provider for array map type.
    status = NmrRegisterProvider(
        &_sample_ebpf_extension_array_map_provider_characteristics,
        &_sample_ebpf_extension_array_map_provider_context,
        &_sample_ebpf_extension_array_map_provider_context.nmr_provider_handle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Register provider for hash map type.
    local_provider_context = &_sample_ebpf_extension_hash_map_provider_context;
    status = NmrRegisterProvider(
        &_sample_ebpf_extension_hash_map_provider_characteristics,
        &_sample_ebpf_extension_hash_map_provider_context,
        &_sample_ebpf_extension_hash_map_provider_context.nmr_provider_handle);

Exit:
    if (!NT_SUCCESS(status)) {
        sample_ebpf_extension_map_provider_unregister();
    }

    return status;
}

_Must_inspect_result_ ebpf_result_t
sample_ebpf_extension_invoke_program(_Inout_ sample_program_context_t* context, _Out_ uint32_t* result)
{
    ebpf_result_t return_value = EBPF_SUCCESS;

    sample_ebpf_extension_hook_provider_t* hook_provider_context = &_sample_ebpf_extension_hook_provider_context;

    sample_ebpf_extension_hook_client_t* hook_client = hook_provider_context->attached_client;

    if (hook_client == NULL) {
        return_value = EBPF_FAILED;
        goto Exit;
    }
    ebpf_program_invoke_function_t invoke_program = hook_client->invoke_program;
    const void* client_binding_context = hook_client->client_binding_context;

    // Run the eBPF program using cached copies of invoke_program and client_binding_context.
    return_value = invoke_program(client_binding_context, context, result);

Exit:
    return return_value;
}

_Must_inspect_result_ ebpf_result_t
sample_ebpf_extension_invoke_batch_begin_program(_Inout_ ebpf_execution_context_state_t* state)
{
    ebpf_result_t return_value = EBPF_SUCCESS;

    sample_ebpf_extension_hook_provider_t* hook_provider_context = &_sample_ebpf_extension_hook_provider_context;

    sample_ebpf_extension_hook_client_t* hook_client = hook_provider_context->attached_client;

    if (hook_client == NULL) {
        return_value = EBPF_FAILED;
        goto Exit;
    }
    ebpf_program_batch_begin_invoke_function_t batch_begin_function = hook_client->begin_batch_program_invoke;
    return_value = batch_begin_function(sizeof(ebpf_execution_context_state_t), state);

Exit:
    return return_value;
}

_Must_inspect_result_ ebpf_result_t
sample_ebpf_extension_invoke_batch_program(
    _Inout_ sample_program_context_t* context, _In_ const ebpf_execution_context_state_t* state, _Out_ uint32_t* result)
{
    ebpf_result_t return_value = EBPF_SUCCESS;

    sample_ebpf_extension_hook_provider_t* hook_provider_context = &_sample_ebpf_extension_hook_provider_context;

    sample_ebpf_extension_hook_client_t* hook_client = hook_provider_context->attached_client;

    if (hook_client == NULL) {
        return_value = EBPF_FAILED;
        goto Exit;
    }
    ebpf_program_batch_invoke_function_t batch_invoke_program = hook_client->batch_program_invoke;
    const void* client_binding_context = hook_client->client_binding_context;

    return_value = batch_invoke_program(client_binding_context, context, result, state);

Exit:
    return return_value;
}

_Must_inspect_result_ ebpf_result_t
sample_ebpf_extension_invoke_batch_end_program(_Inout_ ebpf_execution_context_state_t* state)
{
    ebpf_result_t return_value = EBPF_SUCCESS;

    sample_ebpf_extension_hook_provider_t* hook_provider_context = &_sample_ebpf_extension_hook_provider_context;

    sample_ebpf_extension_hook_client_t* hook_client = hook_provider_context->attached_client;

    if (hook_client == NULL) {
        return_value = EBPF_FAILED;
        goto Exit;
    }
    ebpf_program_batch_end_invoke_function_t batch_end_function = hook_client->end_batch_program_invoke;
    return_value = batch_end_function(state);

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
    sample_program_context_header_t context_header = {
        {0}, request->data, request->data + request_length - FIELD_OFFSET(sample_ebpf_ext_profile_request_t, data)};

    sample_program_context_t* program_context = (sample_program_context_t*)&context_header.context;
    sample_ebpf_extension_hook_provider_t* hook_provider_context = &_sample_ebpf_extension_hook_provider_context;

    sample_ebpf_extension_hook_client_t* hook_client = hook_provider_context->attached_client;

    if (hook_client == NULL) {
        return_value = EBPF_FAILED;
        goto Exit;
    }
    ebpf_program_invoke_function_t invoke_program = hook_client->invoke_program;
    const void* client_binding_context = hook_client->client_binding_context;

    program_context->uint32_data = KeGetCurrentProcessorNumber();

    KeQueryPerformanceCounter(&start);
    if (request->flags & SAMPLE_EBPF_EXT_FLAG_DISPATCH) {
        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
    }
    for (size_t i = 0; i < request->iterations; i++) {
        invoke_program(client_binding_context, program_context, &result);
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

static int64_t
_sample_ebpf_extension_helper_implicit_1(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const sample_program_context_t* context)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);
    UNREFERENCED_PARAMETER(dummy_param5);

    sample_program_context_t* sample_context = (sample_program_context_t*)context;
    return sample_context->helper_data_1;
}

static int64_t
_sample_ebpf_extension_helper_implicit_2(
    uint32_t arg,
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    _In_ const sample_program_context_t* context)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);

    sample_program_context_t* sample_context = (sample_program_context_t*)context;
    return ((uint64_t)sample_context->helper_data_2 + arg);
}

//
// Sample Map Implementation Functions
//
static ebpf_result_t
_sample_hash_map_create(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Outptr_ void** map_context)
{
    sample_hash_map_t* sample_map = NULL;
    ebpf_result_t result = EBPF_SUCCESS;

    UNREFERENCED_PARAMETER(map_type);
    UNREFERENCED_PARAMETER(binding_context);

    ebpf_map_client_dispatch_table_t* client_dispatch_table =
        &((sample_extension_map_provider_binding_context_t*)binding_context)->client_dispatch_table;

    if (key_size == 0 || value_size == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    sample_map = client_dispatch_table->epoch_allocate_cache_aligned_with_tag(
        sizeof(sample_hash_map_t), SAMPLE_EXT_POOL_TAG_DEFAULT);
    if (sample_map == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(sample_map, 0, sizeof(sample_hash_map_t));

    sample_map->base.core.map_type = BPF_MAP_TYPE_SAMPLE_HASH_MAP;
    sample_map->base.core.key_size = key_size;
    sample_map->base.core.value_size = value_size;
    sample_map->base.core.max_entries = max_entries;
    sample_map->base.bucket_count = 16; // Simple fixed bucket count for demonstration
    sample_map->base.entry_count = 0;
    sample_map->client_dispatch = client_dispatch_table;

    // Allocate array of hash buckets
    sample_map->base.buckets = client_dispatch_table->epoch_allocate_cache_aligned_with_tag(
        sizeof(sample_hash_bucket_t) * sample_map->base.bucket_count, SAMPLE_EXT_POOL_TAG_DEFAULT);
    if (sample_map->base.buckets == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Initialize each bucket
    for (uint32_t i = 0; i < sample_map->base.bucket_count; i++) {
        sample_hash_bucket_t* bucket = &sample_map->base.buckets[i];
        bucket->lock = 0;
        bucket->entries = NULL;
        bucket->capacity = 0;
        bucket->count = 0;
    }

    *map_context = (void*)sample_map;

Exit:
    if (result != EBPF_SUCCESS && sample_map != NULL) {
        if (sample_map->base.buckets != NULL) {
            client_dispatch_table->epoch_free_cache_aligned(sample_map->base.buckets);
        }
        client_dispatch_table->epoch_free_cache_aligned(sample_map);
    }
    return result;
}

static void
_sample_hash_map_delete(_In_ _Post_invalid_ void* map)
{
    sample_hash_map_t* sample_map = (sample_hash_map_t*)map;
    if (sample_map == NULL) {
        return;
    }

    ebpf_map_client_dispatch_table_t* client_dispatch_table = sample_map->client_dispatch;

    // Free all bucket arrays
    for (uint32_t i = 0; i < sample_map->base.bucket_count; i++) {
        sample_hash_bucket_t* bucket = &sample_map->base.buckets[i];
        if (bucket->entries != NULL) {
            // Free each entry's key-value data
            for (uint32_t j = 0; j < bucket->count; j++) {
                if (bucket->entries[j].key_value_data != NULL) {
                    client_dispatch_table->epoch_free(bucket->entries[j].key_value_data);
                }
            }
            // Free the entries array
            client_dispatch_table->epoch_free_cache_aligned(bucket->entries);
        }
    }

    if (sample_map->base.buckets != NULL) {
        client_dispatch_table->epoch_free_cache_aligned(sample_map->base.buckets);
    }
    client_dispatch_table->epoch_free_cache_aligned(sample_map);
}

static ebpf_result_t
_sample_hash_map_find_entry(
    _In_ void* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, _Outptr_ uint8_t** value, uint32_t flags)
{
    sample_hash_map_t* sample_map = (sample_hash_map_t*)map;
    ebpf_map_client_dispatch_table_t* client_dispatch_table = sample_map->client_dispatch;

    return _sample_hash_map_find_entry_common(client_dispatch_table, &sample_map->base, key_size, key, value, flags);
}

static ebpf_result_t
_sample_hash_map_update_entry(
    _In_ void* map,
    size_t key_size,
    _In_ const uint8_t* key,
    size_t value_size,
    _In_ const uint8_t* value,
    ebpf_map_option_t option,
    uint32_t flags)
{
    sample_hash_map_t* sample_map = (sample_hash_map_t*)map;
    ebpf_map_client_dispatch_table_t* client_dispatch_table = sample_map->client_dispatch;

    return _sample_hash_map_update_entry_common(
        client_dispatch_table, &sample_map->base, key_size, key, value_size, value, option, flags);
}

static ebpf_result_t
_sample_hash_map_delete_entry(_In_ void* map, size_t key_size, _In_ const uint8_t* key, uint32_t flags)
{
    sample_hash_map_t* sample_map = (sample_hash_map_t*)map;
    ebpf_map_client_dispatch_table_t* client_dispatch_table = sample_map->client_dispatch;

    return _sample_hash_map_delete_entry_common(client_dispatch_table, &sample_map->base, key_size, key, flags);
}

static ebpf_result_t
_sample_hash_map_get_next_key_and_value(
    _In_ void* map,
    size_t key_size,
    _In_ const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value)
{
    sample_hash_map_t* sample_map = (sample_hash_map_t*)map;
    return _sample_hash_map_get_next_key_and_value_common(
        &sample_map->base, key_size, previous_key, next_key, next_value);
}

static void*
_sample_ext_helper_map_lookup_element(
    _In_ const void* map, _In_ const uint8_t* key, uint64_t dummy_param1, uint64_t dummy_param2, uint64_t dummy_param3)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);

    sample_core_map_t** sample_map = (sample_core_map_t**)MAP_CONTEXT(map, _map_context_offset);
    if (*sample_map == NULL) {
        return NULL;
    }
    uint8_t* value = NULL;

    ebpf_result_t result = _sample_map_find_entry(*sample_map, (*sample_map)->key_size, key, &value, 0);
    if (result != EBPF_SUCCESS) {
        return NULL;
    }

    return value;
}

// Sample Array Map Implementation
static ebpf_result_t
_sample_array_map_create(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Outptr_ void** map_context)
{
    sample_array_map_t* sample_map = NULL;
    ebpf_result_t result = EBPF_SUCCESS;

    UNREFERENCED_PARAMETER(map_type);

    ebpf_map_client_dispatch_table_t* client_dispatch_table =
        &((sample_extension_map_provider_binding_context_t*)binding_context)->client_dispatch_table;

    if (key_size != sizeof(uint32_t) || value_size == 0 || max_entries == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    sample_map = client_dispatch_table->epoch_allocate_cache_aligned_with_tag(
        sizeof(sample_array_map_t), SAMPLE_EXT_POOL_TAG_DEFAULT);
    if (sample_map == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(sample_map, 0, sizeof(sample_array_map_t));

    sample_map->base.core.map_type = BPF_MAP_TYPE_SAMPLE_ARRAY_MAP;
    sample_map->base.core.key_size = key_size;
    sample_map->base.core.value_size = value_size;
    sample_map->base.core.max_entries = max_entries;
    sample_map->client_dispatch = client_dispatch_table;

    // Allocate array of values (not entries)
    sample_map->base.data = client_dispatch_table->epoch_allocate_cache_aligned_with_tag(
        (size_t)value_size * max_entries, SAMPLE_EXT_POOL_TAG_DEFAULT);
    if (sample_map->base.data == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    *map_context = (void*)sample_map;

Exit:
    if (result != EBPF_SUCCESS && sample_map != NULL) {
        if (sample_map->base.data != NULL) {
            client_dispatch_table->epoch_free_cache_aligned(sample_map->base.data);
        }
        client_dispatch_table->epoch_free_cache_aligned(sample_map);
    }
    return result;
}

static void
_sample_array_map_delete(_In_ _Post_invalid_ void* map)
{
    sample_array_map_t* array_map = (sample_array_map_t*)map;
    ebpf_map_client_dispatch_table_t* client_dispatch_table = array_map->client_dispatch;

    if (array_map->base.data != NULL) {
        client_dispatch_table->epoch_free_cache_aligned(array_map->base.data);
    }
    client_dispatch_table->epoch_free_cache_aligned(array_map);
}

static ebpf_result_t
_sample_array_map_find_entry(
    _In_ void* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, _Outptr_ uint8_t** value, uint32_t flags)
{
    sample_array_map_t* array_map = (sample_array_map_t*)map;

    return _sample_array_map_find_entry_common(&array_map->base, key_size, key, value, flags);
}

static ebpf_result_t
_sample_array_map_update_entry(
    _In_ void* map,
    size_t key_size,
    _In_ const uint8_t* key,
    size_t value_size,
    _In_ const uint8_t* value,
    ebpf_map_option_t option,
    uint32_t flags)
{
    sample_array_map_t* array_map = (sample_array_map_t*)map;

    return _sample_array_map_update_entry_common(&array_map->base, key_size, key, value_size, value, option, flags);
}

static ebpf_result_t
_sample_array_map_delete_entry(_In_ void* map, size_t key_size, _In_ const uint8_t* key, uint32_t flags)
{
    sample_array_map_t* array_map = (sample_array_map_t*)map;

    return _sample_array_map_delete_entry_common(&array_map->base, key_size, key, flags);
}

static ebpf_result_t
_sample_array_map_get_next_key_and_value(
    _In_ void* map,
    size_t key_size,
    _In_ const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value)
{
    sample_array_map_t* array_map = (sample_array_map_t*)map;

    return _sample_array_map_get_next_key_and_value_common(
        &array_map->base, key_size, previous_key, next_key, next_value);
}

static ebpf_result_t
_sample_map_create(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Outptr_ void** map_context)
{
    if (map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
        return _sample_array_map_create(binding_context, map_type, key_size, value_size, max_entries, map_context);
    } else if (map_type == BPF_MAP_TYPE_SAMPLE_HASH_MAP) {
        return _sample_hash_map_create(binding_context, map_type, key_size, value_size, max_entries, map_context);
    }
    return EBPF_INVALID_ARGUMENT;
}

static void
_sample_map_delete(_In_ _Post_invalid_ void* map)
{
    uint32_t map_type = MAP_TYPE(map);

    if (map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
        _sample_array_map_delete(map);
    } else if (map_type == BPF_MAP_TYPE_SAMPLE_HASH_MAP) {
        _sample_hash_map_delete(map);
    } else {
        __fastfail(FAST_FAIL_INVALID_ARG);
    }
}

static ebpf_result_t
_sample_map_find_entry(
    _In_ void* map,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    _Outptr_ uint8_t** value,
    uint32_t flags)
{
    // Neither of the maps support null key.
    if (key == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    sample_core_map_t* sample_map = (sample_core_map_t*)map;

    if (!(flags & EBPF_MAP_FLAG_HELPER) && key_size != sample_map->key_size) {
        return EBPF_INVALID_ARGUMENT;
    }

    uint32_t map_type = MAP_TYPE(sample_map);
    if (map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
        return _sample_array_map_find_entry(sample_map, key_size, key, value, flags);
    } else if (map_type == BPF_MAP_TYPE_SAMPLE_HASH_MAP) {
        return _sample_hash_map_find_entry(sample_map, key_size, key, value, flags);
    } else {
        return EBPF_INVALID_ARGUMENT;
    }
}

static ebpf_result_t
_sample_map_update_entry(
    _In_ void* map,
    size_t key_size,
    _In_opt_ const uint8_t* key,
    size_t value_size,
    _In_opt_ const uint8_t* value,
    ebpf_map_option_t option,
    uint32_t flags)
{
    if (key == NULL || value == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }
    sample_core_map_t* sample_map = (sample_core_map_t*)map;

    if (!(flags & EBPF_MAP_FLAG_HELPER) && (key_size != sample_map->key_size || value_size != sample_map->value_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    uint32_t map_type = MAP_TYPE(sample_map);
    if (map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
        return _sample_array_map_update_entry(map, key_size, key, value_size, value, option, flags);
    } else if (map_type == BPF_MAP_TYPE_SAMPLE_HASH_MAP) {
        return _sample_hash_map_update_entry(map, key_size, key, value_size, value, option, flags);
    } else {
        return EBPF_INVALID_ARGUMENT;
    }
}

static ebpf_result_t
_sample_map_delete_entry(_In_ void* map, size_t key_size, _In_reads_opt_(key_size) const uint8_t* key, uint32_t flags)
{
    if (key == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }
    sample_core_map_t* sample_map = (sample_core_map_t*)map;
    if (!(flags & EBPF_MAP_FLAG_HELPER) && key_size != sample_map->key_size) {
        return EBPF_INVALID_ARGUMENT;
    }
    uint32_t map_type = MAP_TYPE(sample_map);
    if (map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
        return _sample_array_map_delete_entry(map, key_size, key, flags);
    } else if (map_type == BPF_MAP_TYPE_SAMPLE_HASH_MAP) {
        return _sample_hash_map_delete_entry(map, key_size, key, flags);
    } else {
        return EBPF_INVALID_ARGUMENT;
    }
}

static ebpf_result_t
_sample_map_get_next_key_and_value(
    _In_ void* map,
    size_t key_size,
    _In_ const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value)
{
    uint32_t map_type = MAP_TYPE(map);
    if (map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
        return _sample_array_map_get_next_key_and_value(map, key_size, previous_key, next_key, next_value);
    } else if (map_type == BPF_MAP_TYPE_SAMPLE_HASH_MAP) {
        return _sample_hash_map_get_next_key_and_value(map, key_size, previous_key, next_key, next_value);
    } else {
        return EBPF_INVALID_ARGUMENT;
    }
}

static ebpf_result_t
_sample_map_associate_program(_In_ const void* map_context, _In_ const ebpf_program_type_t* program_type)
{
    UNREFERENCED_PARAMETER(map_context);

    if (memcmp(program_type, &EBPF_PROGRAM_TYPE_SAMPLE, sizeof(ebpf_program_type_t)) != 0) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return EBPF_SUCCESS;
}

static ebpf_result_t
_sample_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    ebpf_result_t result;
    sample_program_context_header_t* context_header = NULL;
    sample_program_context_t* sample_context = NULL;

    *context = NULL;

    // This provider requires context.
    if (context_in == NULL || context_size_in < sizeof(sample_program_context_t)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    context_header = cxplat_allocate(
        CXPLAT_POOL_FLAG_NON_PAGED, sizeof(sample_program_context_header_t), SAMPLE_EXT_POOL_TAG_DEFAULT);
    if (context_header == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    sample_context = (sample_program_context_t*)&context_header->context;

    memcpy(sample_context, context_in, sizeof(sample_program_context_t));

    // Add data_in into the sample_program_context_t.
    if (data_in != NULL && data_size_in > 0) {
        sample_context->data_start = (uint8_t*)data_in;
        sample_context->data_end = (uint8_t*)data_in + data_size_in;
    }

    *context = sample_context;
    context_header = NULL;
    result = EBPF_SUCCESS;

Exit:
    if (context_header != NULL) {
        CXPLAT_FREE(context_header);
    }

    return result;
}

static void
_sample_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    sample_program_context_header_t* context_header = NULL;
    if (context == NULL) {
        return;
    }

    sample_program_context_t* sample_context = (sample_program_context_t*)context;
    context_header = CONTAINING_RECORD(context, sample_program_context_header_t, context);

    if (context_out != NULL && *context_size_out >= sizeof(sample_program_context_t)) {
        memcpy(context_out, context, sizeof(sample_program_context_t));
        *context_size_out = sizeof(sample_program_context_t);
    } else {
        *context_size_out = 0;
    }

    // Copy the app_id to the data_out.
    if (data_out != NULL && *data_size_out >= (size_t)(sample_context->data_end - sample_context->data_start)) {
        memcpy(data_out, sample_context->data_start, sample_context->data_end - sample_context->data_start);
        *data_size_out = sample_context->data_end - sample_context->data_start;
    } else {
        *data_size_out = 0;
    }

    CXPLAT_FREE(context_header);
}
