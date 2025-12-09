// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_EXTENSIBLE_MAPS

#include "ebpf_epoch.h"
#include "ebpf_extensible_maps.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_program.h"
#include "ebpf_tracelog.h"

static ebpf_map_client_dispatch_table_t _ebpf_extensible_map_client_dispatch_table = {
    EBPF_MAP_CLIENT_DISPATCH_TABLE_HEADER,
    ebpf_epoch_allocate_with_tag,
    ebpf_epoch_allocate_cache_aligned_with_tag,
    ebpf_epoch_free,
    ebpf_epoch_free_cache_aligned};

/**
 * @brief Extensible map structure with NMR client components.
 */
__declspec(align(EBPF_CACHE_LINE_SIZE)) typedef struct _ebpf_extensible_map
{
    ebpf_core_map_t core_map; // Base map structure

    ebpf_lock_t lock;                                      // Synchronization lock
    ebpf_map_provider_dispatch_table_t* provider_dispatch; // Provider dispatch table
    void* provider_context;                                // Provider context returned during attach
    NPI_CLIENT_CHARACTERISTICS client_characteristics;
    HANDLE nmr_client_handle;
    NPI_MODULEID module_id;

    EX_RUNDOWN_REF provider_rundown_reference; // Synchronization for provider access
} ebpf_extensible_map_t;

static ebpf_map_client_data_t _ebpf_extensible_map_client_data = {
    EBPF_MAP_CLIENT_DATA_HEADER,
    offsetof(ebpf_extensible_map_t, core_map) + offsetof(ebpf_core_map_t, extensible_map_data),
    &_ebpf_extensible_map_client_dispatch_table};

// NMR client callbacks
static NTSTATUS
_ebpf_extensible_map_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance);

static NTSTATUS
_ebpf_extensible_map_client_detach_provider(_In_ void* client_binding_context);

// Client characteristics template for extensible maps
static const NPI_CLIENT_CHARACTERISTICS _ebpf_extensible_map_client_characteristics = {
    0,
    sizeof(NPI_CLIENT_CHARACTERISTICS),
    _ebpf_extensible_map_client_attach_provider,
    _ebpf_extensible_map_client_detach_provider,
    NULL,
    {
        0,
        sizeof(NPI_REGISTRATION_INSTANCE),
        &EBPF_MAP_INFO_EXTENSION_IID,
        NULL,
        0,
        &_ebpf_extensible_map_client_data,
    },
};

static void
_ebpf_extensible_map_delete(_In_ _Post_ptr_invalid_ ebpf_extensible_map_t* map)
{
    // Wait for rundown completion
    ExWaitForRundownProtectionRelease(&map->provider_rundown_reference);

    // Deregister NMR client
    if (map->nmr_client_handle) {
        NTSTATUS status = NmrDeregisterClient(map->nmr_client_handle);
        if (status == STATUS_PENDING) {
            NmrWaitForClientDeregisterComplete(map->nmr_client_handle);
        } else {
            ebpf_assert(NT_SUCCESS(status));
        }
    }

    ebpf_lock_destroy(&map->lock);
    ebpf_free_cache_aligned(map->provider_dispatch);
    ebpf_free(map->core_map.name.value);
    ebpf_free(map);
}

_Must_inspect_result_ ebpf_result_t
ebpf_extensible_map_create(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_map_t** map)
{
    UNREFERENCED_PARAMETER(inner_map_handle);

    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_extensible_map_t* extensible_map = NULL;
    NTSTATUS status;
    GUID module_id;

    *map = NULL;

    ebpf_assert(ebpf_map_type_is_extensible(map_definition->type));

    result = ebpf_guid_create(&module_id);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }

    // Allocate extensible map
    extensible_map =
        (ebpf_extensible_map_t*)ebpf_allocate_with_tag(sizeof(ebpf_extensible_map_t), EBPF_POOL_TAG_EXTENSIBLE_MAP);
    if (!extensible_map) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(extensible_map, 0, sizeof(ebpf_extensible_map_t));

    extensible_map->core_map.ebpf_map_definition = *map_definition;
    extensible_map->module_id.Guid = module_id;
    extensible_map->module_id.Length = sizeof(NPI_MODULEID);
    extensible_map->module_id.Type = MIT_GUID;

    // Initialize synchronization objects
    ebpf_lock_create(&extensible_map->lock);
    ExInitializeRundownProtection(&extensible_map->provider_rundown_reference);

    // Initialize NMR client characteristics
    extensible_map->client_characteristics = _ebpf_extensible_map_client_characteristics;
    extensible_map->client_characteristics.ClientRegistrationInstance.ModuleId = &extensible_map->module_id;

    // Register as NMR client to find provider
    status =
        NmrRegisterClient(&extensible_map->client_characteristics, extensible_map, &extensible_map->nmr_client_handle);
    if (status != STATUS_SUCCESS) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "NmrRegisterClient failed for extensible map",
            status);
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    if (extensible_map->provider_dispatch == NULL) {
        // No provider found for map type.
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Failed to find provider for extensible map type",
            extensible_map->core_map.ebpf_map_definition.type);
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    // Acquire rundown before creating map.
    if (!ExAcquireRundownProtection(&extensible_map->provider_rundown_reference)) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Failed to acquire rundown for extensible map type",
            extensible_map->core_map.ebpf_map_definition.type);
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    // Create extension map
    result = extensible_map->provider_dispatch->create_map_function(
        extensible_map->provider_context,
        extensible_map->core_map.ebpf_map_definition.type,
        extensible_map->core_map.ebpf_map_definition.key_size,
        extensible_map->core_map.ebpf_map_definition.value_size,
        extensible_map->core_map.ebpf_map_definition.max_entries,
        // &extensible_map->core_map.ebpf_map_definition,
        &extensible_map->core_map.extensible_map_data);

    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Failed to create extension map for extensible map type",
            extensible_map->core_map.ebpf_map_definition.type);

        // Release rundown.
        ExReleaseRundownProtection(&extensible_map->provider_rundown_reference);
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    *map = &extensible_map->core_map;
    extensible_map = NULL;

Done:
    if (extensible_map) {
        _ebpf_extensible_map_delete(extensible_map);
    }
    return result;
}

void
ebpf_extensible_map_delete(_In_ _Post_ptr_invalid_ ebpf_core_map_t* map)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);

    // Call provider to delete the map.
    extensible_map->provider_dispatch->delete_map_function(extensible_map->core_map.extensible_map_data);

    // Now that the map is deleted, release the rundown reference acquired during map creation.
    ExReleaseRundownProtection(&extensible_map->provider_rundown_reference);

    _ebpf_extensible_map_delete(extensible_map);
}

static NTSTATUS
_ebpf_extensible_map_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    ebpf_extensible_map_t* extensible_map = (ebpf_extensible_map_t*)client_context;
    const ebpf_map_provider_data_t* provider_data =
        (const ebpf_map_provider_data_t*)provider_registration_instance->NpiSpecificCharacteristics;
    NTSTATUS status = STATUS_SUCCESS;
    void* provider_binding_context;
    void* provider_dispatch;
    ebpf_map_provider_dispatch_table_t* provider_dispatch_table = NULL;
    bool lock_acquired = false;
    ebpf_lock_state_t state = 0;

    if (!ebpf_validate_map_provider_data(provider_data)) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Provider data validation failed for extensible map");
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    // Check if map type matches any of the supported types
    if ((uint32_t)extensible_map->core_map.ebpf_map_definition.type != provider_data->map_type) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_VERBOSE,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Map type not supported by provider",
            extensible_map->core_map.ebpf_map_definition.type);
        status = STATUS_NOT_SUPPORTED;
        goto Done;
    }

    // Provider supports the requested map type.

    // Create a cache-aligned copy of the dispatch table for hot path performance.
    provider_dispatch_table = (ebpf_map_provider_dispatch_table_t*)ebpf_allocate_cache_aligned_with_tag(
        sizeof(ebpf_map_provider_dispatch_table_t), EBPF_POOL_TAG_EXTENSIBLE_MAP);
    if (!provider_dispatch_table) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    // Acquire lock and update dispatch table
    state = ebpf_lock_lock(&extensible_map->lock);
    lock_acquired = true;

    if (extensible_map->provider_dispatch != NULL) {
        // Provider already attached. This should not happen.
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Provider already attached for map type",
            extensible_map->core_map.ebpf_map_definition.type);
        status = STATUS_INVALID_DEVICE_STATE;
        goto Done;
    }

    memcpy(
        provider_dispatch_table,
        provider_data->dispatch_table,
        min(sizeof(ebpf_map_provider_dispatch_table_t), provider_data->dispatch_table->header.size));
    extensible_map->provider_dispatch = provider_dispatch_table;
    provider_dispatch_table = NULL;

    ebpf_lock_unlock(&extensible_map->lock, state);

    // Found extension map provider. Attach to it.
#pragma warning(push)
#pragma warning(disable : 6387) // NULL is allowed for client dispatch
    status = NmrClientAttachProvider(
        nmr_binding_handle, extensible_map, NULL, &provider_binding_context, &provider_dispatch);
#pragma warning(pop)

    // Acquire lock to update state after successful attachment
    state = ebpf_lock_lock(&extensible_map->lock);
    lock_acquired = true;

    if (status != STATUS_SUCCESS) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "NmrClientAttachProvider failed for extensible map",
            status);

        ebpf_free((void*)extensible_map->provider_dispatch);
        extensible_map->provider_dispatch = NULL;
        // extensible_map->provider_attached = false;
        goto Done;
    } else {
        extensible_map->provider_context = provider_binding_context;
    }

    ebpf_lock_unlock(&extensible_map->lock, state);
    lock_acquired = false;

Done:
    if (lock_acquired) {
        ebpf_lock_unlock(&extensible_map->lock, state);
    }

    ebpf_free(provider_dispatch_table);
    return status;
}

static NTSTATUS
_ebpf_extensible_map_client_detach_provider(_In_ void* client_binding_context)
{
    ebpf_extensible_map_t* map = (ebpf_extensible_map_t*)client_binding_context;

    // Wait for all provider operations to complete
    ExWaitForRundownProtectionRelease(&map->provider_rundown_reference);

    return STATUS_SUCCESS;
}

static ebpf_result_t
_ebpf_extensible_map_update_element_with_handle(
    _In_ ebpf_map_t* map, _In_ const uint8_t* key, uintptr_t value_handle, ebpf_map_option_t option)
{
    UNREFERENCED_PARAMETER(map);
    UNREFERENCED_PARAMETER(key);
    UNREFERENCED_PARAMETER(value_handle);
    UNREFERENCED_PARAMETER(option);

    // Extensible maps don't support handle-based updates by default
    return EBPF_OPERATION_NOT_SUPPORTED;
}

_Must_inspect_result_ ebpf_result_t
ebpf_extensible_map_find_entry(
    _Inout_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    _Outptr_ uint8_t** value,
    int flags)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);
    ebpf_result_t result = EBPF_OPERATION_NOT_SUPPORTED;

    // Get provider dispatch.
    ebpf_map_provider_dispatch_table_t* provider_dispatch = extensible_map->provider_dispatch;
    ebpf_assert(provider_dispatch != NULL);
    // Call provider's find function
    __analysis_assume(provider_dispatch != NULL);
    if (provider_dispatch->find_element_function == NULL) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    result = provider_dispatch->find_element_function(
        extensible_map->core_map.extensible_map_data, key_size, key, value, (uint32_t)flags);

    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_extensible_map_update_entry(
    _Inout_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    ebpf_map_option_t option,
    int flags)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);
    ebpf_result_t result = EBPF_OPERATION_NOT_SUPPORTED;

    // Get provider dispatch.
    ebpf_map_provider_dispatch_table_t* provider_dispatch = extensible_map->provider_dispatch;
    ebpf_assert(provider_dispatch != NULL);
    // Call provider's update function
    __analysis_assume(provider_dispatch != NULL);
    if (provider_dispatch->update_element_function == NULL) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    result = provider_dispatch->update_element_function(
        extensible_map->core_map.extensible_map_data, key_size, key, value_size, value, option, (uint32_t)flags);

    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_extensible_map_delete_entry(
    _In_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, int flags)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);
    ebpf_result_t result = EBPF_OPERATION_NOT_SUPPORTED;

    // Get provider dispatch.
    ebpf_map_provider_dispatch_table_t* provider_dispatch = extensible_map->provider_dispatch;
    ebpf_assert(provider_dispatch != NULL);
    // Call provider's delete function
    __analysis_assume(provider_dispatch != NULL);
    if (provider_dispatch->delete_element_function == NULL) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    result = provider_dispatch->delete_element_function(
        extensible_map->core_map.extensible_map_data, key_size, key, (uint32_t)flags);

    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_extensible_map_get_next_key_and_value(
    _Inout_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);
    ebpf_result_t result = EBPF_OPERATION_NOT_SUPPORTED;

    // Get provider dispatch.
    ebpf_map_provider_dispatch_table_t* provider_dispatch = extensible_map->provider_dispatch;
    ebpf_assert(provider_dispatch != NULL);
    // Call provider's get next key and value function
    __analysis_assume(provider_dispatch != NULL);
    if (provider_dispatch->get_next_key_and_value_function == NULL) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    result = provider_dispatch->get_next_key_and_value_function(
        extensible_map->core_map.extensible_map_data, key_size, previous_key, next_key, next_value);

    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_extensible_map_associate_program(_Inout_ ebpf_map_t* map, _In_ const struct _ebpf_program* program)
{
    ebpf_result_t result;
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);
    ebpf_program_type_t program_type = ebpf_program_type_uuid(program);

    // Get provider dispatch.
    ebpf_map_provider_dispatch_table_t* provider_dispatch = extensible_map->provider_dispatch;
    ebpf_assert(provider_dispatch != NULL && provider_dispatch->associate_program_function != NULL);
    // Call provider's associate program function
    __analysis_assume(provider_dispatch != NULL);
    __analysis_assume(provider_dispatch->associate_program_function != NULL);
    result = provider_dispatch->associate_program_function(extensible_map->core_map.extensible_map_data, &program_type);

    return result;
}
