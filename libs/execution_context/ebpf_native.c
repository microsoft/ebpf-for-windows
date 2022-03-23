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

#ifndef GUID_NULL
static const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

typedef uint64_t (*helper_function_address)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
typedef void (*ebpf_free_native_t)(ebpf_native_t* native_object);

static void
_ebpf_native_unload_workitem(_In_ const void* module_id);

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
    bool loaded;
    wchar_t* service_name;
    bool detaching;
    bool unloading;
    ebpf_lock_t lock;
    ebpf_native_map_t* maps;
    size_t map_count;
    ebpf_native_program_t* programs;
    size_t program_count;
    ebpf_handle_t client_binding_handle;
} ebpf_native_t;

static GUID _ebpf_native_npi_id = {/* c847aac8-a6f2-4b53-aea3-f4a94b9a80cb */
                                   0xc847aac8,
                                   0xa6f2,
                                   0x4b53,
                                   {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};
static ebpf_extension_provider_t* _ebpf_native_provider = NULL;

#define EBPF_CLIENT_TABLE_BUCKET_COUNT 64
static ebpf_lock_t _ebpf_native_client_table_lock = {0};
static _Requires_lock_held_(&_ebpf_native_client_table_lock) ebpf_hash_table_t* _ebpf_native_client_table = NULL;

ebpf_result_t
ebpf_native_load_driver(_In_z_ const wchar_t* service_name);
void
ebpf_native_unload_driver(_In_z_ const wchar_t* service_name);

static void
_ebpf_native_cleanup_maps(_In_reads_(map_count) _Frees_ptr_ ebpf_native_map_t* maps, size_t map_count)
{
    for (uint32_t count = 0; count < map_count; count++) {
        ebpf_native_map_t* map = &maps[count];
        if (map->pin_path.value && map->pinned && !map->reused) {
            ebpf_core_update_pinning(UINT64_MAX, &map->pin_path);
        }
        if (map->pin_path.value) {
#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory '*maps.pin_path.value'
            ebpf_free(map->pin_path.value);
#pragma warning(pop)
        }
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
        if (programs[i].handle != ebpf_handle_invalid) {
            ebpf_handle_close(programs[i].handle);
        }
    }

    ebpf_free(programs);
}

static void
_ebpf_native_cleanup_module(_In_ ebpf_native_t* native_module)
{
    _ebpf_native_cleanup_maps(native_module->maps, native_module->map_count);
    _ebpf_native_cleanup_programs(native_module->programs, native_module->program_count);

    ebpf_free(native_module->service_name);
    ebpf_lock_destroy(&native_module->lock);
}

void
ebpf_native_acquire_reference(_In_ ebpf_native_t* native_module)
{
    ebpf_assert(native_module->reference_count != 0);
    ebpf_interlocked_increment_int32(&native_module->reference_count);
}

void
ebpf_native_release_reference(_In_opt_ ebpf_native_t* native_module)
{
    uint32_t new_ref_count;
    GUID* module_id = NULL;
    ebpf_result_t result = EBPF_SUCCESS;
    bool lock_acquired = false;
    ebpf_lock_state_t module_lock_state = 0;

    if (!native_module)
        return;

    ebpf_assert(native_module->reference_count != 0);

    new_ref_count = ebpf_interlocked_decrement_int32(&native_module->reference_count);

    if (new_ref_count == 1) {
        // Check if all the program references have been released. If that
        // is the case, explicitly unload the driver, if it is safe to do so.
        if (ebpf_is_preemptible_work_item_supported()) {
            bool unload = false;
            module_lock_state = ebpf_lock_lock(&native_module->lock);
            lock_acquired = true;
            if (!native_module->detaching && !native_module->unloading) {
                // If the module is not yet unloading or detaching, and reference
                // count is 1, it means all the program references have been
                // released.
                module_id = (GUID*)ebpf_allocate(sizeof(GUID));
                if (module_id == NULL) {
                    result = EBPF_NO_MEMORY;
                    goto Done;
                }
                unload = true;
                *module_id = native_module->client_id;
            }
            ebpf_lock_unlock(&native_module->lock, module_lock_state);
            lock_acquired = false;
            if (unload) {
                ebpf_preemptible_work_item_t* work_item = NULL;
                result = ebpf_allocate_preemptible_work_item(&work_item, _ebpf_native_unload_workitem, module_id);
                if (result != EBPF_SUCCESS) {
                    goto Done;
                }
                ebpf_queue_preemptible_work_item(work_item);
            }
        }
    } else if (new_ref_count == 0) {
        ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
        // Delete entry from hash table
        ebpf_hash_table_delete(_ebpf_native_client_table, (const uint8_t*)&native_module->client_id);
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);

        // All references to the module have been released. Safe to complete the detach callback.
        ebpf_provider_detach_client_complete(&_ebpf_native_npi_id, native_module->client_binding_handle);

        // Cleanup the native module.
        _ebpf_native_cleanup_module(native_module);
    }

Done:
    if (lock_acquired) {
        ebpf_lock_unlock(&native_module->lock, module_lock_state);
    }
    if (result != EBPF_SUCCESS) {
        ebpf_free(module_id);
    }
    return;
}

/**
 * @brief Unload driver for all the native modules in _ebpf_native_client_table
 *
 */
static void
_ebpf_native_unload_all()
{
    ebpf_result_t result;
    ebpf_lock_state_t state;
    bool lock_acquired = false;

    for (;;) {
        GUID module_id;
        state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
        lock_acquired = true;
        result = ebpf_hash_table_next_key(_ebpf_native_client_table, (const uint8_t*)NULL, (uint8_t*)&module_id);
        if (result != EBPF_SUCCESS) {
            ebpf_assert(result == EBPF_NO_MORE_KEYS);
            break;
        }
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
        ebpf_native_unload(&module_id);
    }

    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    }
}

void
ebpf_native_terminate()
{
    // Unload all the native module drivers.
    _ebpf_native_unload_all();

    // ebpf_provider_unload is blocking call until all the
    // native modules have been detached.
    ebpf_provider_unload(_ebpf_native_provider);

    // All native modules should be cleaned up by now.
    ebpf_assert(ebpf_hash_table_key_count(_ebpf_native_client_table) == 0);

    ebpf_hash_table_destroy(_ebpf_native_client_table);
    ebpf_lock_destroy(&_ebpf_native_client_table_lock);
}

static ebpf_result_t
_ebpf_native_client_attach_callback(
    ebpf_handle_t client_binding_handle,
    _In_ void* context,
    _In_ const GUID* client_id,
    _In_ void* client_binding_context,
    _In_ const ebpf_extension_data_t* client_data,
    _In_ const ebpf_extension_dispatch_table_t* client_dispatch_table)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(client_binding_context);
    UNREFERENCED_PARAMETER(client_dispatch_table);

    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state = 0;
    ebpf_native_t** native_module = NULL;
    bool lock_acquired = false;
    metadata_table_t* table = NULL;
    ebpf_native_t* client_context = ebpf_allocate(sizeof(ebpf_native_t));

    if (!client_context) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    table = (metadata_table_t*)client_data;
    if (!table->programs || !table->maps) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    ebpf_lock_create(&client_context->lock);
    // Acquire "attach" reference. Released when detach is called for this module.
    client_context->reference_count = 1;
    client_context->client_id = *client_id;
    client_context->initialized = false;
    client_context->table = table;
    client_context->client_binding_handle = client_binding_handle;

    // Insert the new client context in the hash table.
    state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    lock_acquired = true;
    result = ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)client_id, (uint8_t**)&native_module);
    if (result == EBPF_SUCCESS) {
        result = EBPF_OBJECT_ALREADY_EXISTS;
        goto Done;
    }
    result = ebpf_hash_table_update(
        _ebpf_native_client_table,
        (const uint8_t*)client_id,
        (const uint8_t*)&client_context,
        EBPF_HASH_TABLE_OPERATION_INSERT);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
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
    UNREFERENCED_PARAMETER(context);

    // 1. Find the entry in the hash table using "client_id"
    // 2. Release the "attach" reference on the native module.
    // 3. Return EBPF_PENDING
    ebpf_result_t result = EBPF_PENDING;
    ebpf_native_t** existing_native_module = NULL;
    ebpf_native_t* native_module = NULL;
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    bool lock_acquired = true;
    if (ebpf_hash_table_find(
            _ebpf_native_client_table, (const uint8_t*)client_id, (uint8_t**)&existing_native_module) != EBPF_SUCCESS) {
        result = EBPF_SUCCESS;
        goto Done;
    }
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    lock_acquired = false;
    native_module = *existing_native_module;
    state = ebpf_lock_lock(&native_module->lock);
    ebpf_assert(native_module->detaching == false);
    native_module->detaching = true;
    ebpf_lock_unlock(&native_module->lock, state);
    ebpf_native_release_reference(native_module);

Done:
    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    }
    return result;
}

ebpf_result_t
ebpf_native_initiate()
{
    ebpf_result_t return_value;
    GUID provider_module_id;
    bool hash_table_created = false;

    ebpf_lock_create(&_ebpf_native_client_table_lock);

    return_value = ebpf_hash_table_create(
        &_ebpf_native_client_table,
        ebpf_allocate,
        ebpf_free,
        sizeof(GUID),
        sizeof(ebpf_native_t*),
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
        if (hash_table_created) {
            ebpf_hash_table_destroy(_ebpf_native_client_table);
        }
        ebpf_lock_destroy(&_ebpf_native_client_table_lock);
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
            size_t name_length = strnlen_s(maps[i].name, BPF_OBJ_NAME_LEN);
            if (name_length == 0 || name_length >= BPF_OBJ_NAME_LEN ||
                prefix_length + name_length + 1 >= EBPF_MAX_PIN_PATH_LENGTH) {
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
            memcpy(native_maps[i].pin_path.value + prefix_length, "/", 1);
            memcpy(native_maps[i].pin_path.value + prefix_length + 1, maps[i].name, name_length);
        } else {
            native_maps[i].pin_path.value = NULL;
            native_maps[i].pin_path.length = 0;
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
        map_name.value = NULL;

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
        native_module->map_count = 0;
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
    for (uint16_t i = 0; i < map_count; i++) {
        map_handles[i] = native_maps[map_indices[i]].handle;
    }

    result = ebpf_core_resolve_maps(program->handle, map_count, map_handles, map_addresses);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Update the addresses in the map entries.
    for (uint16_t i = 0; i < map_count; i++) {
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
    UNREFERENCED_PARAMETER(native_module);
    ebpf_result_t result;
    uint32_t* helper_ids = NULL;
    helper_function_address* helper_addresses = NULL;
    uint16_t helper_count = program->entry->helper_count;
    helper_function_entry_t* helpers = program->entry->helpers;

    if (helper_count == 0) {
        // No helpers called by this program.
        return EBPF_SUCCESS;
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
    for (uint16_t i = 0; i < helper_count; i++) {
        helper_ids[i] = helpers[i].helper_id;
    }

    result = ebpf_core_resolve_helper(program->handle, helper_count, helper_ids, (uint64_t*)helper_addresses);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Update the addresses in the helper entries.
    for (uint16_t i = 0; i < helper_count; i++) {
        helpers[i].address = helper_addresses[i];
    }

Done:
    ebpf_free(helper_ids);
    ebpf_free(helper_addresses);
    return result;
}

static _Requires_lock_held_(native_module->lock) void _ebpf_native_initialize_helpers_for_program(
    _In_ ebpf_native_t* native_module, _In_ ebpf_native_program_t* program)
{
    UNREFERENCED_PARAMETER(native_module);
    size_t helper_count = program->entry->helper_count;
    helper_function_entry_t* helpers = program->entry->helpers;
    // Initialize the helper entries.
    for (size_t i = 0; i < helper_count; i++) {
        helpers[i].address = NULL;
        if (helpers[i].helper_id == BPF_FUNC_tail_call) {
            helpers[i].tail_call = true;
        }
    }
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

        _ebpf_native_initialize_helpers_for_program(native_module, native_program);

        program_name_length = strnlen_s(program->program_name, BPF_OBJ_NAME_LEN);
        section_name_length = strnlen_s(program->section_name, BPF_OBJ_NAME_LEN);
        if (program_name_length == 0 || program_name_length >= BPF_OBJ_NAME_LEN || section_name_length == 0 ||
            section_name_length >= BPF_OBJ_NAME_LEN) {
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

        parameters.program_type = *program->program_type;
        parameters.expected_attach_type = (program->expected_attach_type ? *program->expected_attach_type : GUID_NULL);

        memcpy(program_name, program->program_name, program_name_length);
        parameters.program_name.value = program_name;
        parameters.program_name.length = program_name_length;

        memcpy(section_name, program->section_name, section_name_length);
        parameters.section_name.value = section_name;
        parameters.section_name.length = section_name_length;

        parameters.file_name.value = NULL;
        parameters.file_name.length = 0;

        result = ebpf_program_create_and_initialize(&parameters, &native_program->handle);
        if (result != EBPF_SUCCESS) {
            break;
        }

        ebpf_free(program_name);
        ebpf_free(section_name);
        program_name = NULL;
        section_name = NULL;

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
        native_module->program_count = 0;
    }

    ebpf_free(program_name);
    ebpf_free(section_name);
    return result;
}

size_t
_ebpf_native_get_count_of_maps(_In_ const ebpf_native_t* native_module)
{
    map_entry_t* maps = NULL;
    size_t count_of_maps;
    native_module->table->maps(&maps, &count_of_maps);

    return count_of_maps;
}

size_t
_ebpf_native_get_count_of_programs(_In_ const ebpf_native_t* native_module)
{
    program_entry_t* programs = NULL;
    size_t count_of_programs;
    native_module->table->programs(&programs, &count_of_programs);

    return count_of_programs;
}

ebpf_result_t
ebpf_native_load(
    _In_ const wchar_t* service_name,
    uint16_t service_name_length,
    _In_ const GUID* module_id,
    _Out_ size_t* count_of_maps,
    _Out_ size_t* count_of_programs)
{
    ebpf_result_t result;
    ebpf_lock_state_t hash_table_state = 0;
    ebpf_lock_state_t state = 0;
    bool lock_acquired = false;
    ebpf_native_t* native_module = NULL;
    ebpf_native_t** existing_native_module = NULL;
    wchar_t* local_service_name = NULL;

    local_service_name = ebpf_allocate((size_t)service_name_length + 2);
    if (local_service_name == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    memcpy(local_service_name, (uint8_t*)service_name, service_name_length);

    ebpf_native_load_driver(local_service_name);

    // Find the native entry in hash table.
    hash_table_state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    lock_acquired = true;
    result =
        ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&existing_native_module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        goto Done;
    }
    native_module = *existing_native_module;
    state = ebpf_lock_lock(&native_module->lock);
    if (native_module->initialized) {
        // This client has already been initialized.
        result = EBPF_OBJECT_ALREADY_EXISTS;
        ebpf_lock_unlock(&native_module->lock, state);
        goto Done;
    }
    if (native_module->detaching || native_module->unloading) {
        // This client is already detaching / unloading.
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        ebpf_lock_unlock(&native_module->lock, state);
        goto Done;
    }
    native_module->initialized = true;
    native_module->service_name = local_service_name;
    ebpf_lock_unlock(&native_module->lock, state);

    // Get map and program count;
    *count_of_maps = _ebpf_native_get_count_of_maps(native_module);
    *count_of_programs = _ebpf_native_get_count_of_programs(native_module);

Done:
    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, hash_table_state);
        lock_acquired = false;
    }
    if (result != EBPF_SUCCESS) {
        ebpf_free(local_service_name);
    }

    return result;
}

ebpf_result_t
ebpf_native_load_programs(
    _In_ const GUID* module_id,
    size_t count_of_map_handles,
    _Out_writes_(count_of_map_handles) ebpf_handle_t* map_handles,
    size_t count_of_program_handles,
    _Out_writes_(count_of_program_handles) ebpf_handle_t* program_handles)
{
    ebpf_result_t result;
    ebpf_lock_state_t state = 0;
    ebpf_lock_state_t native_state = 0;
    bool lock_acquired = false;
    bool native_lock_acquired = false;
    ebpf_native_t** existing_native_module = NULL;
    ebpf_native_t* native_module = NULL;
    wchar_t* local_service_name = NULL;

    // Find the native entry in hash table.
    state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    lock_acquired = true;
    result =
        ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&existing_native_module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        goto Done;
    }
    native_module = *existing_native_module;
    native_state = ebpf_lock_lock(&native_module->lock);
    native_lock_acquired = true;
    if (native_module->loaded) {
        // This client has already been loaded.
        result = EBPF_OBJECT_ALREADY_EXISTS;
        goto Done;
    }

    if (native_module->unloading || native_module->detaching) {
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    // Create maps.
    result = _ebpf_native_create_maps(native_module);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Create programs.
    result = _ebpf_native_load_programs(native_module);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    native_module->loaded = true;

    ebpf_lock_unlock(&native_module->lock, native_state);
    native_lock_acquired = false;

    ebpf_assert(count_of_map_handles == native_module->map_count);
    ebpf_assert(count_of_program_handles == native_module->program_count);

    for (int i = 0; i < count_of_map_handles; i++) {
        map_handles[i] = native_module->maps[i].handle;
        native_module->maps[i].handle = ebpf_handle_invalid;
    }

    for (int i = 0; i < count_of_program_handles; i++) {
        program_handles[i] = native_module->programs[i].handle;
        native_module->programs[i].handle = ebpf_handle_invalid;
    }

Done:
    if (native_lock_acquired) {
        ebpf_lock_unlock(&native_module->lock, native_state);
        native_lock_acquired = false;
    }
    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
        lock_acquired = false;
    }
    if (result != EBPF_SUCCESS) {
        ebpf_free(local_service_name);
    }

    return result;
}

ebpf_result_t
ebpf_native_get_count_of_programs(_In_ const GUID* module_id, _Out_ size_t* count_of_programs)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state = 0;
    ebpf_native_t** native_module = NULL;

    // Find the native entry in hash table.
    state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    result = ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&native_module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        goto Done;
    }

    *count_of_programs = _ebpf_native_get_count_of_programs(*native_module);

Done:
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    return result;
}

ebpf_result_t
ebpf_native_get_count_of_maps(_In_ const GUID* module_id, _Out_ size_t* count_of_maps)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state = 0;
    ebpf_native_t** native_module = NULL;

    // Find the native entry in hash table.
    state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    result = ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&native_module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        goto Done;
    }

    *count_of_maps = _ebpf_native_get_count_of_maps(*native_module);

Done:
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    return result;
}

ebpf_result_t
ebpf_native_unload(_In_ const GUID* module_id)
{
    ebpf_result_t result;
    ebpf_lock_state_t state = 0;
    ebpf_lock_state_t native_state = 0;
    bool lock_acquired = false;
    bool module_lock_acquired = false;
    ebpf_native_t** existing_native_module = NULL;
    ebpf_native_t* native_module = NULL;
    wchar_t* service_name = NULL;
    size_t service_name_length;
    bool unload_module = false;

    // Find the native entry in hash table.
    state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    lock_acquired = true;
    result =
        ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&existing_native_module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        goto Done;
    }
    native_module = *existing_native_module;
    native_state = ebpf_lock_lock(&native_module->lock);
    module_lock_acquired = true;
    if (native_module->unloading) {
        // If module is already unloading, skip unloading it again.
        result = EBPF_SUCCESS;
        goto Done;
    }
    native_module->unloading = true;
    unload_module = true;

    // It is possible that the module is also detaching at the same time and
    // the module memory can be freed immediately after the hash table lock is
    // released. Create a copy of the service name to use later to unload driver.
    service_name_length = (wcslen(native_module->service_name) * 2) + 2;
    service_name = ebpf_allocate(service_name_length);
    if (service_name == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    memcpy(service_name, native_module->service_name, service_name_length);

    ebpf_lock_unlock(&native_module->lock, native_state);
    module_lock_acquired = false;
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    lock_acquired = false;

    if (unload_module)
        ebpf_native_unload_driver(service_name);

Done:
    if (module_lock_acquired) {
        ebpf_lock_unlock(&native_module->lock, native_state);
        module_lock_acquired = false;
    }
    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
        lock_acquired = false;
    }

    ebpf_free(service_name);

    return result;
}

static void
_ebpf_native_unload_workitem(_In_ const void* module_id)
{
    ebpf_native_unload((GUID*)module_id);
}
