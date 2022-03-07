// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_core.h"
#include "ebpf_native.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_protocol.h"
#include "ebpf_handle.h"

#define DEFAULT_PIN_ROOT_PATH "/ebpf/global"
#define EBPF_MAX_PIN_PATH_LENGTH 256

typedef uint64_t (*helper_function_address)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);

typedef struct _ebpf_native_map
{
    map_entry_t* entry;
    struct _ebpf_native_map* inner_map;
    ebpf_handle_t handle;
    ebpf_handle_t inner_map_handle;
    int32_t original_fd;
    int32_t inner_map_original_fd;
    ebpf_utf8_string_t pin_path;
    bool reused;
    bool pinned;
} ebpf_native_map_t;

typedef struct _ebpf_native_program
{
    program_entry_t* entry;
    ebpf_handle_t handle;
} ebpf_native_program_t;

typedef struct _ebpf_native
{
    GUID client_id;
    metadata_table_t* table;
    volatile int32_t reference_count;
    bool initialized;
    wchar_t* service_name;
    bool detaching;
    ebpf_lock_t lock;
    ebpf_native_map_t* maps;
    size_t map_count;
    ebpf_native_program_t* programs;
    size_t program_count;
    helper_function_entry_t* helpers;
    size_t helper_count;
} ebpf_native_t;

static GUID _ebpf_native_npi_id = {/* c847aac8-a6f2-4b53-aea3-f4a94b9a80cb */
                                   0xc847aac8,
                                   0xa6f2,
                                   0x4b53,
                                   {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};
static ebpf_extension_provider_t* _ebpf_native_provider = NULL;

#define EBPF_CLIENT_TABLE_BUCKET_COUNT 64
static ebpf_lock_t _ebpf_client_table_lock = {0};
static _Requires_lock_held_(&_ebpf_client_table_lock) ebpf_hash_table_t* _ebpf_client_table = NULL;

ebpf_result_t
ebpf_native_load_module(_In_z_ const wchar_t* service_name);
void
ebpf_native_unload_module(_In_z_ const wchar_t* service_name);

void
_ebpf_native_unload(ebpf_native_t* native)
{
    // This function will do the cleanup for the native clients.
    // 1. stop service
    // 2. free the entry.
    UNREFERENCED_PARAMETER(native);
}

void
ebpf_native_acquire_reference(ebpf_native_t* native)
{
    ebpf_assert(native->reference_count != 0);
    ebpf_interlocked_increment_int32(&native->reference_count);
}

void
ebpf_native_release_reference(ebpf_native_t* native)
{
    uint32_t new_ref_count;

    if (!native)
        return;

    ebpf_assert(native->reference_count != 0);

    new_ref_count = ebpf_interlocked_decrement_int32(&native->reference_count);

    if (new_ref_count == 0) {
        ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_client_table_lock);
        // Delete entry from hash table
        ebpf_hash_table_delete(_ebpf_client_table, (const uint8_t*)&native->client_id);
        ebpf_lock_unlock(&_ebpf_client_table_lock, state);
        // Unload the driver.
        ebpf_native_unload_module(native->service_name);
    }
}

void
ebpf_native_terminate()
{
    if (_ebpf_client_table != NULL) {
        // TODO: Use "ebpf_hash_table_next_key" to iterate over
        // all the entries from the table, and delete them.
        GUID next_key;
        GUID* previous_key = NULL;
        while (ebpf_hash_table_next_key(_ebpf_client_table, (const uint8_t*)previous_key, (uint8_t*)&next_key) ==
               EBPF_SUCCESS) {
            previous_key = &next_key;
        }
        ebpf_assert(ebpf_hash_table_key_count(_ebpf_client_table) == 0);
        ebpf_hash_table_destroy(_ebpf_client_table);
        _ebpf_client_table = NULL;
    }
    ebpf_provider_unload(_ebpf_native_provider);
}

static ebpf_result_t
_ebpf_native_client_attach_callback(
    _In_ void* context,
    _In_ const GUID* client_id,
    _In_ void* client_binding_context,
    _In_ const ebpf_extension_data_t* client_data,
    _In_ const ebpf_extension_dispatch_table_t* client_dispatch_table)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state = 0;
    ebpf_native_t* local_client_context = NULL;
    bool lock_acquired = false;
    ebpf_native_t* client_context = ebpf_allocate(sizeof(ebpf_native_t));

    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(client_binding_context);
    UNREFERENCED_PARAMETER(client_dispatch_table);

    if (!client_context) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    client_context->reference_count = 1;
    client_context->client_id = *client_id;
    client_context->initialized = false;
    client_context->table = (metadata_table_t*)client_data;

    // Insert the new client context in the hash table.
    state = ebpf_lock_lock(&_ebpf_client_table_lock);
    lock_acquired = true;
    result = ebpf_hash_table_find(_ebpf_client_table, (const uint8_t*)client_id, (uint8_t**)&local_client_context);
    if (result == EBPF_SUCCESS) {
        result = EBPF_OBJECT_ALREADY_EXISTS;
        goto Done;
    }
    result = ebpf_hash_table_update(
        _ebpf_client_table,
        (const uint8_t*)client_id,
        (const uint8_t*)&client_context,
        EBPF_HASH_TABLE_OPERATION_INSERT);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_client_table_lock, state);
        lock_acquired = false;
    }
    if (result != EBPF_SUCCESS) {
        ebpf_free(client_context);
    }
    return result;
}

static ebpf_result_t
_ebpf_native_client_detach_callback(_In_ void* context, _In_ const GUID* client_id)
{
    // ANUSA TODO:
    // Call a function exposed from ebpf_core which will iterate over all the
    // programs and check which programs have the pointer to this ebpf_native.
    // Then mark those programs as "inactive". and release the reference to the
    // ebpf_native.

    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(client_id);

    /*
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
    */

    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_native_initiate()
{
    ebpf_result_t return_value;
    GUID provider_module_id;
    bool hash_table_created = false;
    return_value = ebpf_hash_table_create(
        &_ebpf_client_table,
        ebpf_allocate,
        ebpf_free,
        sizeof(GUID),
        sizeof(void*),
        EBPF_CLIENT_TABLE_BUCKET_COUNT,
        NULL);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }
    hash_table_created = true;

    return_value = ebpf_guid_create(&provider_module_id);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_provider_load(
        &_ebpf_native_provider,
        &_ebpf_native_npi_id,
        &provider_module_id,
        NULL,
        NULL,
        NULL,
        NULL,
        _ebpf_native_client_attach_callback,
        _ebpf_native_client_detach_callback);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    if (return_value != EBPF_SUCCESS) {
        ebpf_native_terminate();
    }

    return return_value;
}

static ebpf_native_map_t*
_ebpf_native_get_next_map_to_create(_In_ ebpf_native_map_t* maps, size_t map_count)
{
    for (uint32_t i = 0; i < map_count; i++) {
        ebpf_native_map_t* map = &maps[i];
        if (map->handle != ebpf_handle_invalid) {
            // Already created.
            continue;
        }
        if (map->entry->definition.type != BPF_MAP_TYPE_ARRAY_OF_MAPS &&
            map->entry->definition.type != BPF_MAP_TYPE_HASH_OF_MAPS) {
            return map;
        }
        if (map->inner_map == NULL) {
            // This map requires an inner map template, look up which one.
            for (uint32_t j = 0; j < map_count; j++) {
                ebpf_native_map_t* inner_map = &maps[i];
                if (!inner_map) {
                    continue;
                }
                if (inner_map->original_fd == map->inner_map_original_fd) {
                    map->inner_map = inner_map;
                    break;
                }
            }
            if (map->inner_map == NULL) {
                // We can't create this map because there is no inner template.
                continue;
            }
        }
        if (map->inner_map->handle == ebpf_handle_invalid) {
            // We need to create the inner map template first.
            continue;
        }

        return map;
    }

    // There are no maps left that we can create.
    return NULL;
}

static ebpf_result_t
_ebpf_native_initialize_maps(_In_ ebpf_native_map_t* native_maps, _In_ map_entry_t* maps, size_t map_count)
{
    ebpf_result_t result = EBPF_SUCCESS;
    const int ORIGINAL_FD_OFFSET = 1;
    for (uint32_t i = 0; i < map_count; i++) {
        if (maps[i].definition.pinning != PIN_NONE && maps[i].definition.pinning != PIN_GLOBAL_NS) {
            result = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        native_maps[i].entry = &maps[i];
        native_maps[i].original_fd = i + ORIGINAL_FD_OFFSET;
        native_maps[i].handle = ebpf_handle_invalid;
        maps[i].address = NULL;

        if (maps[i].definition.pinning == PIN_GLOBAL_NS) {
            // Construct the pin path.
            size_t prefix_length = strnlen(DEFAULT_PIN_ROOT_PATH, EBPF_MAX_PIN_PATH_LENGTH);
            size_t name_length = strnlen(maps[i].name, EBPF_MAX_PIN_PATH_LENGTH);
            if (prefix_length + name_length + 1 >= EBPF_MAX_PIN_PATH_LENGTH) {
                result = EBPF_INVALID_ARGUMENT;
                goto Done;
            }

            native_maps[i].pin_path.value = ebpf_allocate(prefix_length + name_length + 1);
            if (native_maps[i].pin_path.value == NULL) {
                result = EBPF_NO_MEMORY;
                goto Done;
            }
            native_maps[i].pin_path.length = prefix_length + name_length + 1;
            memcpy(native_maps[i].pin_path.value, DEFAULT_PIN_ROOT_PATH, prefix_length);
            native_maps[i].pin_path.value[prefix_length] = '/';
            memcpy(native_maps[i].pin_path.value + prefix_length + 1, maps[i].name, name_length);
        }
    }

    // Populate inner map fd.
    for (uint32_t i = 0; i < map_count; i++) {
        ebpf_map_definition_in_file_t* definition = &(native_maps[i].entry->definition);
        int32_t inner_map_original_fd = -1;
        if (definition->type == BPF_MAP_TYPE_ARRAY_OF_MAPS || definition->type == BPF_MAP_TYPE_HASH_OF_MAPS) {
            if (definition->inner_map_idx != 0) {
                inner_map_original_fd = definition->inner_map_idx + ORIGINAL_FD_OFFSET;
            } else if (definition->inner_id != 0) {
                for (uint32_t j = 0; j < map_count; j++) {
                    ebpf_map_definition_in_file_t* inner_definition = &(native_maps[j].entry->definition);
                    if (inner_definition->id == definition->inner_id && i != j) {
                        inner_map_original_fd = j + ORIGINAL_FD_OFFSET;
                        break;
                    }
                }
            }
        }
        native_maps[i].inner_map_original_fd = inner_map_original_fd;
    }

Done:
    return result;
}

static inline bool
_ebpf_native_is_map_in_map(ebpf_native_map_t* map)
{
    if (map->entry->definition.type == BPF_MAP_TYPE_HASH_OF_MAPS ||
        map->entry->definition.type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
        return true;
    }

    return false;
}

static ebpf_result_t
_ebpf_native_validate_map(_In_ ebpf_native_map_t* map, ebpf_handle_t original_map_handle)
{
    // Validate that the existing map definition matches with this new map.
    struct bpf_map_info info;
    ebpf_core_object_t* object;
    ebpf_handle_t inner_map_handle = ebpf_handle_invalid;
    uint16_t info_size = (uint16_t)sizeof(info);
    ebpf_result_t result = ebpf_reference_object_by_handle(original_map_handle, EBPF_OBJECT_UNKNOWN, &object);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = ebpf_map_get_info((ebpf_map_t*)object, (uint8_t*)&info, &info_size);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (info.type != map->entry->definition.type || info.key_size != map->entry->definition.key_size ||
        info.value_size != map->entry->definition.value_size ||
        info.max_entries != map->entry->definition.max_entries) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Extra checks for map-in-map.
    if (_ebpf_native_is_map_in_map(map)) {
        ebpf_native_map_t* inner_map = map->inner_map;
        ebpf_assert(inner_map != NULL);

        if (info.inner_map_id == EBPF_ID_NONE) {
            // The original map is pinned but its template is not initialized yet.
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        // For map-in-map, validate the inner map template also.
        result = ebpf_core_get_handle_by_id(EBPF_OBJECT_MAP, info.inner_map_id, &inner_map_handle);
        if (result != EBPF_SUCCESS) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        result = _ebpf_native_validate_map(inner_map, inner_map_handle);
    }

Exit:
    ebpf_object_release_reference(object);
    return result;
}

static ebpf_result_t
_ebpf_native_reuse_map(_In_ ebpf_native_map_t* map)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t handle = ebpf_handle_invalid;
    // Check if a map is already present with this pin path.
    ebpf_core_get_pinned_object(&map->pin_path, &handle);
    if (handle == ebpf_handle_invalid) {
        goto Exit;
    }

    // Recursively validate that the map definition matches with the existing
    // map.
    result = _ebpf_native_validate_map(map, handle);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // The map can be reused. Populate map handle.
    map->handle = handle;
    map->reused = true;
    map->pinned = true;

Exit:
    if (result != EBPF_SUCCESS) {
        ebpf_handle_close(handle);
    }
    return result;
}

static void
_ebpf_native_cleanup_maps(_In_ ebpf_native_map_t* maps, size_t map_count)
{
    for (uint32_t count = 0; count < map_count; count++) {
        ebpf_native_map_t* map = &maps[count];
        if (map->pin_path.value && map->pinned && !map->reused) {
            ebpf_core_update_pinning(UINT64_MAX, &map->pin_path);
        }
        ebpf_free(map->pin_path.value);
        if (map->handle != ebpf_handle_invalid) {
            ebpf_handle_close(map->handle);
        }
    }

    ebpf_free(maps);
}

static void
_ebpf_native_cleanup_programs(_In_ ebpf_native_program_t* programs, size_t count_of_programs)
{
    for (uint32_t i = 0; i < count_of_programs; i++) {
        ebpf_handle_close(programs[i].handle);
    }

    ebpf_free(programs);
}

static _Requires_lock_held_(native_module->lock) ebpf_result_t
    _ebpf_native_create_maps(_In_ ebpf_native_t* native_module)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_native_map_t* native_maps = NULL;
    map_entry_t* maps = NULL;
    size_t map_count = 0;
    ebpf_utf8_string_t map_name = {0};
    ebpf_map_definition_in_memory_t map_definition = {0};

    // Get the maps
    native_module->table->maps(&maps, &map_count);
    if (map_count == 0) {
        return EBPF_SUCCESS;
    }

    native_module->maps = (ebpf_native_map_t*)ebpf_allocate(map_count * sizeof(ebpf_native_map_t));
    if (native_module->maps == NULL) {
        return EBPF_NO_MEMORY;
    }
    native_module->map_count = map_count;
    native_maps = native_module->maps;

    result = _ebpf_native_initialize_maps(native_maps, maps, map_count);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    for (uint32_t count = 0; count < map_count; count++) {
        ebpf_native_map_t* native_map = _ebpf_native_get_next_map_to_create(native_maps, map_count);
        if (native_map == NULL) {
            // Any remaining maps cannot be created.
            result = EBPF_INVALID_OBJECT;
            break;
        }

        if (native_map->entry->definition.pinning == PIN_GLOBAL_NS) {
            result = _ebpf_native_reuse_map(native_map);
            if (result != EBPF_SUCCESS) {
                break;
            }
            if (native_map->reused) {
                continue;
            }
        }

        ebpf_handle_t inner_map_handle = (native_map->inner_map) ? native_map->inner_map->handle : ebpf_handle_invalid;
        // map_name.value = native_map->entry->name;
        // ANUSA TODO: Make sure to free the string copy being created below.
        map_name.length = strlen(native_map->entry->name);
        map_name.value = (uint8_t*)ebpf_allocate(map_name.length);
        if (map_name.value == NULL) {
            result = EBPF_NO_MEMORY;
            break;
        }
        memcpy(map_name.value, native_map->entry->name, map_name.length);
        map_definition.size = sizeof(map_definition);
        map_definition.type = native_map->entry->definition.type;
        map_definition.key_size = native_map->entry->definition.key_size;
        map_definition.value_size = native_map->entry->definition.value_size;
        map_definition.max_entries = native_map->entry->definition.max_entries;

        result = ebpf_core_create_map(&map_name, &map_definition, inner_map_handle, &native_map->handle);
        if (result != EBPF_SUCCESS) {
            break;
        }

        ebpf_free(map_name.value);

        // If pin_path is set and the map is not yet pinned, pin it now.
        if (native_map->pin_path.value != NULL && !native_map->pinned) {
            result = ebpf_core_update_pinning(native_map->handle, &native_map->pin_path);
            if (result != EBPF_SUCCESS) {
                break;
            }
            native_map->pinned = true;
        }
    }

Done:
    if (result != EBPF_SUCCESS) {
        _ebpf_native_cleanup_maps(native_module->maps, native_module->map_count);
        native_module->maps = NULL;
    }
    if (map_name.value != NULL) {
        ebpf_free(map_name.value);
    }

    return result;
}

static void
_ebpf_native_initialize_programs(
    _In_ ebpf_native_program_t* native_programs, _In_ program_entry_t* programs, size_t program_count)
{
    for (uint32_t i = 0; i < program_count; i++) {
        native_programs[i].entry = &programs[i];
        native_programs[i].handle = ebpf_handle_invalid;
    }
}

static _Requires_lock_held_(native_module->lock) ebpf_result_t
    _ebpf_native_resolve_maps_for_program(_In_ ebpf_native_t* native_module, _In_ ebpf_native_program_t* program)
{
    ebpf_result_t result;
    ebpf_handle_t* map_handles = NULL;
    uintptr_t* map_addresses = NULL;
    uint16_t* map_indices = program->entry->referenced_map_indices;
    uint16_t map_count = program->entry->referenced_map_count;
    ebpf_native_map_t* native_maps = native_module->maps;

    if (map_count == 0) {
        // No maps associated with this program.
        return EBPF_SUCCESS;
    }

    // Validate all map indices are within range.
    for (uint32_t i = 0; i < map_count; i++) {
        if (map_indices[i] >= native_module->map_count) {
            return EBPF_INVALID_ARGUMENT;
        }
    }

    map_handles = ebpf_allocate(map_count * sizeof(ebpf_handle_t));
    if (map_handles == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    map_addresses = ebpf_allocate(map_count * sizeof(uintptr_t));
    if (map_addresses == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    // Iterate over the map indices to get all the handles.
    for (uint32_t i = 0; i < map_count; i++) {
        map_handles[i] = native_maps[map_indices[i]].handle;
    }

    result = ebpf_core_resolve_maps(program->handle, map_count, map_handles, map_addresses);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Update the addresses in the map entries.
    for (uint32_t i = 0; i < map_count; i++) {
        // Same map can be used in multiple programs and hence resolved multiple times.
        // Verify that the address of a map does not change.
        if (native_maps[map_indices[i]].entry->address != NULL &&
            native_maps[map_indices[i]].entry->address != (void*)map_addresses[i]) {
            result = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        native_maps[map_indices[i]].entry->address = (void*)map_addresses[i];
    }

Done:
    ebpf_free(map_handles);
    ebpf_free(map_addresses);
    return result;
}

static _Requires_lock_held_(native_module->lock) ebpf_result_t
    _ebpf_native_resolve_helpers_for_program(_In_ ebpf_native_t* native_module, _In_ ebpf_native_program_t* program)
{
    ebpf_result_t result;
    uint32_t* helper_ids = NULL;
    helper_function_address* helper_addresses = NULL;
    uint16_t* helper_indices = program->entry->referenced_helper_indices;
    uint16_t helper_count = program->entry->referenced_helper_count;
    helper_function_entry_t* helpers = native_module->helpers;

    if (helper_count == 0) {
        // No helpers called by this program.
        return EBPF_SUCCESS;
    }

    // Validate all helper indices are within range.
    for (uint32_t i = 0; i < helper_count; i++) {
        if (helper_indices[i] >= native_module->helper_count) {
            return EBPF_INVALID_ARGUMENT;
        }
    }

    helper_ids = ebpf_allocate(helper_count * sizeof(uint32_t));
    if (helper_ids == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    helper_addresses = ebpf_allocate(helper_count * sizeof(helper_function_address));
    if (helper_addresses == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    // Iterate over the helper indices to get all the helper ids.
    for (uint32_t i = 0; i < helper_count; i++) {
        helper_ids[i] = helpers[helper_indices[i]].helper_id;
    }

    result = ebpf_core_resolve_helper(program->handle, helper_count, helper_ids, (uint64_t*)helper_addresses);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Update the addresses in the helper entries.
    for (uint32_t i = 0; i < helper_count; i++) {
        // Same helper can be used in multiple programs and hence resolved multiple times.
        // Verify that the address of a helper function does not change.
        if (helpers[helper_indices[i]].address != NULL && helpers[helper_indices[i]].address != helper_addresses[i]) {
            result = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        helpers[helper_indices[i]].address = helper_addresses[i];
    }

Done:
    ebpf_free(helper_ids);
    ebpf_free(helper_addresses);
    return result;
}

static _Requires_lock_held_(native_module->lock) ebpf_result_t
    _ebpf_native_load_programs(_In_ ebpf_native_t* native_module)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_native_program_t* native_programs = NULL;
    program_entry_t* programs = NULL;
    size_t program_count = 0;
    size_t program_name_length = 0;
    size_t section_name_length = 0;
    uint8_t* program_name = NULL;
    uint8_t* section_name = NULL;

    // Get the programs.
    native_module->table->programs(&programs, &program_count);
    if (program_count == 0 || programs == NULL) {
        return EBPF_INVALID_OBJECT;
    }

    native_module->programs = (ebpf_native_program_t*)ebpf_allocate(program_count * sizeof(ebpf_native_program_t));
    if (native_module->programs == NULL) {
        return EBPF_NO_MEMORY;
    }
    native_module->program_count = program_count;
    native_programs = native_module->programs;

    _ebpf_native_initialize_programs(native_programs, programs, program_count);

    for (uint32_t count = 0; count < program_count; count++) {
        ebpf_native_program_t* native_program = &native_programs[count];
        program_entry_t* program = native_program->entry;
        ebpf_program_parameters_t parameters = {0};

        program_name_length = strnlen_s(program->program_name, EBPF_MAX_PIN_PATH_LENGTH);
        section_name_length = strnlen_s(program->section_name, EBPF_MAX_PIN_PATH_LENGTH);
        if (program_name_length >= EBPF_MAX_PIN_PATH_LENGTH || section_name_length >= EBPF_MAX_PIN_PATH_LENGTH) {
            result = EBPF_INVALID_ARGUMENT;
            break;
        }

        program_name = ebpf_allocate(program_name_length);
        if (program_name == NULL) {
            result = EBPF_NO_MEMORY;
            break;
        }
        section_name = ebpf_allocate(section_name_length);
        if (section_name == NULL) {
            result = EBPF_NO_MEMORY;
            break;
        }

        // ANUSA TODO: Free the duplicate strings being created below.
        parameters.program_type = program->program_type;
        memcpy(parameters.program_name.value, program_name, program_name_length);
        parameters.program_name.length = program_name_length;
        memcpy(parameters.section_name.value, section_name, section_name_length);
        parameters.section_name.length = section_name_length;
        parameters.file_name.value = NULL;
        parameters.file_name.length = 0;

        result = ebpf_program_create_and_initialize(&parameters, &native_program->handle);
        if (result != EBPF_SUCCESS) {
            break;
        }

        ebpf_free(program_name);
        ebpf_free(section_name);

        // Load machine code.
        result = ebpf_core_load_code(
            native_program->handle, EBPF_CODE_NATIVE, native_module, (uint8_t*)native_program->entry->function, 0);
        if (result != EBPF_SUCCESS) {
            break;
        }

        // Resolve and associate maps with the program.
        result = _ebpf_native_resolve_maps_for_program(native_module, native_program);
        if (result != EBPF_SUCCESS) {
            break;
        }

        // Resolve helper addresses.
        result = _ebpf_native_resolve_helpers_for_program(native_module, native_program);
        if (result != EBPF_SUCCESS) {
            break;
        }
    }

    if (result != EBPF_SUCCESS) {
        _ebpf_native_cleanup_programs(native_module->programs, native_module->program_count);
        native_module->programs = NULL;
    }

    ebpf_free(program_name);
    ebpf_free(section_name);
    return result;
}

static _Requires_lock_held_(native_module->lock) void _ebpf_native_initialize_helpers(_In_ ebpf_native_t* native_module)
{
    // Get the helper entries.
    native_module->table->helpers(&(native_module->helpers), &native_module->helper_count);
    for (uint32_t i = 0; i < native_module->helper_count; i++) {
        native_module->helpers[i].address = NULL;
        if (native_module->helpers[i].helper_id == BPF_FUNC_tail_call) {
            native_module->helpers[i].tail_call = true;
        }
    }
}

ebpf_result_t
ebpf_native_load(
    _In_ const wchar_t* service_name,
    uint16_t service_name_length,
    _In_ const GUID* module_id,
    _Out_ uint32_t* count_of_map_handles,
    _Out_ ebpf_handle_t* map_handles,
    _Out_ uint32_t* count_of_program_handles,
    _Out_ ebpf_handle_t* program_handles)
{
    // NTSTATUS status;
    ebpf_result_t result;
    ebpf_lock_state_t state = 0;
    bool lock_acquired = false;
    ebpf_native_t* local_client_context = NULL;
    wchar_t* local_service_name = NULL;
    // GUID module_id;

    // ANUSA TODO: return program and map handles to the caller.
    // Also cleanup all the handles saved in the ebpf_native module.
    UNREFERENCED_PARAMETER(program_handles);
    UNREFERENCED_PARAMETER(count_of_program_handles);
    UNREFERENCED_PARAMETER(map_handles);
    UNREFERENCED_PARAMETER(count_of_map_handles);

    service_name = ebpf_allocate(service_name_length + 2);
    if (local_service_name == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    memcpy(local_service_name, (uint8_t*)service_name, service_name_length);
    /*
    result = ebpf_guid_create(&module_id);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }
    // ANUSA TODO: Update the registry with the module ID which is generated above.
    */

    result = ebpf_native_load_module(local_service_name);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Find the native entry in hash table.
    state = ebpf_lock_lock(&_ebpf_client_table_lock);
    lock_acquired = true;
    result = ebpf_hash_table_find(_ebpf_client_table, (const uint8_t*)module_id, (uint8_t**)&local_client_context);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        goto Done;
    }
    if (local_client_context->initialized) {
        // This client has already been loaded / initialized.
        result = EBPF_OBJECT_ALREADY_EXISTS;
        goto Done;
    }
    local_client_context->initialized = true;
    local_client_context->service_name = local_service_name;

    // Create maps.
    result = _ebpf_native_create_maps(local_client_context);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Initialize helpers.
    _ebpf_native_initialize_helpers(local_client_context);

    // Create programs.
    result = _ebpf_native_load_programs(local_client_context);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // TODO: Return the list of all the map and program handles back to the caller.

Done:
    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_client_table_lock, state);
        lock_acquired = false;
    }
    if (result != EBPF_SUCCESS) {
        ebpf_free(local_service_name);
    }

    return result;
}

/*
void ebpf_native_get_maps(_In_ const ebpf_native_t* native, _Out_ ebpf_native_map_t** maps, _Out_ size_t* count_of_maps)
{
    native->table->maps(maps, count_of_maps);
}

void ebpf_native_get_programs(_In_ const ebpf_native_t* native, _Out_ ebpf_native_program_t** programs, _Out_ size_t*
count_of_programs)
{
    native->table->programs(programs, count_of_programs);
}
*/