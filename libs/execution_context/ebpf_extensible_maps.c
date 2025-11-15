// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_EXTENSIBLE_MAPS

#include "ebpf_extensible_maps.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_tracelog.h"

// NMR client callbacks
static NTSTATUS
_ebpf_extensible_map_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance);

static NTSTATUS
_ebpf_extensible_map_client_detach_provider(_In_ void* client_binding_context);

// Map operation implementation
static ebpf_result_t
_ebpf_extensible_map_find_element(_In_ ebpf_map_t* map, _In_ const uint8_t* key, _Outptr_ uint8_t** data);

static ebpf_result_t
_ebpf_extensible_map_associate_program(_In_ ebpf_map_t* map, _In_ const ebpf_program_t* program);

static ebpf_result_t
_ebpf_extensible_map_update_element(
    _In_ ebpf_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option);

static ebpf_result_t
_ebpf_extensible_map_update_element_with_handle(
    _In_ ebpf_map_t* map, _In_ const uint8_t* key, uintptr_t value_handle, ebpf_map_option_t option);

static ebpf_result_t
_ebpf_extensible_map_delete_element(_In_ ebpf_map_t* map, _In_ const uint8_t* key);

static ebpf_result_t
_ebpf_extensible_map_get_next_key(_In_ ebpf_map_t* map, _In_opt_ const uint8_t* previous_key, _Out_ uint8_t* next_key);

// Extensible map function table
static const ebpf_map_function_table_t _ebpf_extensible_map_function_table = {
    _ebpf_extensible_map_find_element,
    _ebpf_extensible_map_update_element,
    _ebpf_extensible_map_update_element_with_handle,
    _ebpf_extensible_map_delete_element,
    _ebpf_extensible_map_get_next_key,
    _ebpf_extensible_map_associate_program};

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
        &EBPF_MAP_EXTENSION_IID,
        NULL,
        0,
        NULL,
    },
};

_Must_inspect_result_ bool
ebpf_map_type_is_extensible(uint32_t map_type)
{
    return map_type >= 4096;
}

static void
_ebpf_extensible_map_delete(_In_ _Post_ptr_invalid_ ebpf_core_object_t* object)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(object, ebpf_extensible_map_t, core_map.object);

    // Wait for rundown completion
    ExWaitForRundownProtectionRelease(&extensible_map->provider_rundown_reference);

    // Call provider's map_delete if provider is attached
    ebpf_lock_state_t state = ebpf_lock_lock(&extensible_map->lock);
    if (extensible_map->provider_attached && extensible_map->provider && extensible_map->provider->map_delete) {
        extensible_map->provider->map_delete(extensible_map->extension_map_context);
    }
    ebpf_lock_unlock(&extensible_map->lock, state);

    // Deregister NMR client
    if (extensible_map->nmr_client_handle) {
        NmrDeregisterClient(extensible_map->nmr_client_handle);
    }

    ebpf_lock_destroy(&extensible_map->lock);
    ebpf_free(extensible_map);
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

    *map = NULL;

    // Validate input
    if (!ebpf_map_type_is_extensible(map_definition->type)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Allocate extensible map
    extensible_map = (ebpf_extensible_map_t*)ebpf_allocate_with_tag(sizeof(ebpf_extensible_map_t), EBPF_POOL_TAG_MAP);
    if (!extensible_map) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(extensible_map, 0, sizeof(ebpf_extensible_map_t));

    // Initialize base map structure
    result = ebpf_map_initialize(
        &extensible_map->core_map, map_definition, &_ebpf_extensible_map_function_table, _ebpf_extensible_map_delete);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Initialize synchronization objects
    ebpf_lock_create(&extensible_map->lock);
    ExInitializeRundownProtection(&extensible_map->provider_rundown_reference);

    // Initialize NMR client characteristics
    extensible_map->client_characteristics = _ebpf_extensible_map_client_characteristics;
    extensible_map->client_characteristics.ClientRegistrationInstance.ModuleId = &extensible_map->module_id;

    // Set up module ID with map type
    extensible_map->module_id.Length = sizeof(NPI_MODULEID);
    extensible_map->module_id.Type = MIT_GUID;
    memcpy(&extensible_map->module_id.Guid, &map_definition->type, sizeof(uint32_t));

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

    // Check if provider attached successfully
    ebpf_lock_state_t state = ebpf_lock_lock(&extensible_map->lock);
    bool provider_attached = extensible_map->provider_attached;
    ebpf_lock_unlock(&extensible_map->lock, state);

    if (!provider_attached) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_MAP,
            "No provider found for extensible map type",
            map_definition->type);
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    *map = &extensible_map->core_map;
    extensible_map = NULL;

Done:
    if (extensible_map) {
        ebpf_map_delete(&extensible_map->core_map);
    }
    return result;
}

static NTSTATUS
_ebpf_extensible_map_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    ebpf_extensible_map_t* extensible_map = (ebpf_extensible_map_t*)client_context;
    const ebpf_map_extension_data_t* provider_data =
        (const ebpf_map_extension_data_t*)provider_registration_instance->NpiSpecificCharacteristics;
    ebpf_extensible_map_client_binding_t* binding_context = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ebpf_result_t result;

    if (!provider_data || !provider_data->provider_interface) {
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    // Check if map type matches
    if (provider_data->supported_map_type != extensible_map->core_map.ebpf_map_definition.type) {
        status = STATUS_NOT_SUPPORTED;
        goto Done;
    }

    // Allocate binding context
    binding_context = (ebpf_extensible_map_client_binding_t*)ebpf_allocate_with_tag(
        sizeof(ebpf_extensible_map_client_binding_t), EBPF_POOL_TAG_MAP);
    if (!binding_context) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    binding_context->nmr_binding_handle = nmr_binding_handle;
    binding_context->provider_interface = provider_data->provider_interface;
    binding_context->supported_map_type = provider_data->supported_map_type;

    // Call provider's map_create
    result = provider_data->provider_interface->map_create(
        extensible_map->core_map.ebpf_map_definition.type,
        extensible_map->core_map.ebpf_map_definition.key_size,
        extensible_map->core_map.ebpf_map_definition.value_size,
        extensible_map->core_map.ebpf_map_definition.max_entries,
        &extensible_map->core_map.ebpf_map_definition,
        &extensible_map->extension_map_context);

    if (result != EBPF_SUCCESS) {
        status = STATUS_UNSUCCESSFUL;
        goto Done;
    }

    // Update extensible map state
    ebpf_lock_state_t state = ebpf_lock_lock(&extensible_map->lock);
    extensible_map->provider = provider_data->provider_interface;
    extensible_map->provider_attached = true;
    ebpf_lock_unlock(&extensible_map->lock, state);

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_MAP,
        "Successfully attached extensible map provider for type",
        provider_data->supported_map_type);

Done:
    if (status != STATUS_SUCCESS && binding_context) {
        ebpf_free(binding_context);
        binding_context = NULL;
    }
    return status;
}

static NTSTATUS
_ebpf_extensible_map_client_detach_provider(_In_ void* client_binding_context)
{
    ebpf_extensible_map_client_binding_t* binding_context =
        (ebpf_extensible_map_client_binding_t*)client_binding_context;

    if (binding_context) {
        ebpf_free(binding_context);
    }
    return STATUS_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_extensible_map_invoke_with_provider(
    _In_ ebpf_extensible_map_t* extensible_map,
    _In_ void* operation_context,
    _In_ ebpf_result_t (*operation)(const ebpf_extensible_map_provider_t* provider, void* context))
{
    ebpf_result_t result;
    const ebpf_extensible_map_provider_t* provider;

    // Acquire rundown protection
    if (!ExAcquireRundownProtection(&extensible_map->provider_rundown_reference)) {
        return EBPF_INVALID_OBJECT;
    }

    // Get provider under lock
    ebpf_lock_state_t state = ebpf_lock_lock(&extensible_map->lock);
    provider = extensible_map->provider_attached ? extensible_map->provider : NULL;
    ebpf_lock_unlock(&extensible_map->lock, state);

    if (!provider) {
        result = EBPF_INVALID_OBJECT;
        goto Done;
    }

    // Call the operation
    result = operation(provider, operation_context);

Done:
    // Release rundown protection
    ExReleaseRundownProtection(&extensible_map->provider_rundown_reference);
    return result;
}

// Map operation context structures
typedef struct _map_lookup_context
{
    const uint8_t* key;
    uint8_t** data;
} map_lookup_context_t;

typedef struct _map_update_context
{
    const uint8_t* key;
    const uint8_t* value;
    uint64_t flags;
} map_update_context_t;

typedef struct _map_delete_context
{
    const uint8_t* key;
} map_delete_context_t;

typedef struct _map_next_key_context
{
    const uint8_t* previous_key;
    uint8_t* next_key;
} map_next_key_context_t;

// Provider operation wrappers
static ebpf_result_t
_provider_lookup_operation(const ebpf_extensible_map_provider_t* provider, void* context)
{
    map_lookup_context_t* lookup_context = (map_lookup_context_t*)context;
    if (!provider->map_lookup) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    // Note: For extensible maps, we return the value directly rather than a pointer
    // This is different from global maps but follows the provider interface design
    return provider->map_lookup(
        ((ebpf_extensible_map_t*)context)->extension_map_context, lookup_context->key, *lookup_context->data);
}

static ebpf_result_t
_provider_update_operation(const ebpf_extensible_map_provider_t* provider, void* context)
{
    map_update_context_t* update_context = (map_update_context_t*)context;
    if (!provider->map_update) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return provider->map_update(
        ((ebpf_extensible_map_t*)context)->extension_map_context,
        update_context->key,
        update_context->value,
        update_context->flags);
}

static ebpf_result_t
_provider_delete_operation(const ebpf_extensible_map_provider_t* provider, void* context)
{
    map_delete_context_t* delete_context = (map_delete_context_t*)context;
    if (!provider->map_delete_element) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return provider->map_delete_element(((ebpf_extensible_map_t*)context)->extension_map_context, delete_context->key);
}

static ebpf_result_t
_provider_next_key_operation(const ebpf_extensible_map_provider_t* provider, void* context)
{
    map_next_key_context_t* next_key_context = (map_next_key_context_t*)context;
    if (!provider->map_get_next_key) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return provider->map_get_next_key(
        ((ebpf_extensible_map_t*)context)->extension_map_context,
        next_key_context->previous_key,
        next_key_context->next_key);
}

// Map function table implementations
static ebpf_result_t
_ebpf_extensible_map_find_element(_In_ ebpf_map_t* map, _In_ const uint8_t* key, _Outptr_ uint8_t** data)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);
    map_lookup_context_t context = {key, data};

    return ebpf_extensible_map_invoke_with_provider(extensible_map, &context, _provider_lookup_operation);
}

static ebpf_result_t
_ebpf_extensible_map_update_element(
    _In_ ebpf_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);
    map_update_context_t context = {key, value, (uint64_t)option};

    return ebpf_extensible_map_invoke_with_provider(extensible_map, &context, _provider_update_operation);
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

static ebpf_result_t
_ebpf_extensible_map_delete_element(_In_ ebpf_map_t* map, _In_ const uint8_t* key)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);
    map_delete_context_t context = {key};

    return ebpf_extensible_map_invoke_with_provider(extensible_map, &context, _provider_delete_operation);
}

static ebpf_result_t
_ebpf_extensible_map_get_next_key(_In_ ebpf_map_t* map, _In_opt_ const uint8_t* previous_key, _Out_ uint8_t* next_key)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);
    map_next_key_context_t context = {previous_key, next_key};

    return ebpf_extensible_map_invoke_with_provider(extensible_map, &context, _provider_next_key_operation);
}

static ebpf_result_t
_ebpf_extensible_map_associate_program(_In_ ebpf_map_t* map, _In_ const ebpf_program_t* program)
{
    ebpf_extensible_map_t* extensible_map = CONTAINING_RECORD(map, ebpf_extensible_map_t, core_map);
    ebpf_result_t result = EBPF_SUCCESS;

    // Get provider under lock
    ebpf_lock_state_t state = ebpf_lock_lock(&extensible_map->lock);
    const ebpf_extensible_map_provider_t* provider =
        extensible_map->provider_attached ? extensible_map->provider : NULL;
    ebpf_lock_unlock(&extensible_map->lock, state);

    if (!provider) {
        result = EBPF_INVALID_OBJECT;
        goto Done;
    }

    // Validate association if provider supports it
    if (provider->validate_map_program_association) {
        // Get program type from program
        // Note: This would require access to program internals
        // For now, we'll allow all associations
        result = EBPF_SUCCESS;
    }

Done:
    return result;
}