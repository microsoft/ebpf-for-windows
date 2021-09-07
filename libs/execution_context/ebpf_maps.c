// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"

#define PAD_CACHE(X) ((X + EBPF_CACHE_LINE_SIZE - 1) & ~(EBPF_CACHE_LINE_SIZE - 1))

typedef struct _ebpf_core_map
{
    ebpf_object_t object;
    ebpf_utf8_string_t name;
    ebpf_map_definition_in_memory_t ebpf_map_definition;
    ebpf_lock_t lock;
    uint32_t original_value_size;
    struct _ebpf_core_map* inner_map_template;
    uint8_t* data;
} ebpf_core_map_t;

typedef struct _ebpf_core_object_map
{
    ebpf_core_map_t core_map;
    bool is_program_type_set;
    ebpf_program_type_t program_type;
} ebpf_core_object_map_t;

_Ret_notnull_ static const ebpf_program_type_t*
_get_map_program_type(_In_ const ebpf_object_t* object)
{
    const ebpf_core_object_map_t* map = (const ebpf_core_object_map_t*)object;
    return &map->program_type;
}

typedef struct _ebpf_map_function_table
{
    ebpf_core_map_t* (*create_map)(_In_ const ebpf_map_definition_in_memory_t* map_definition);
    void (*delete_map)(_In_ ebpf_core_map_t* map);
    ebpf_result_t (*associate_program)(_In_ ebpf_map_t* map, _In_ const ebpf_program_t* program);
    uint8_t* (*find_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_object_t* (*get_object_from_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*update_entry)(
        _In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option);
    ebpf_result_t (*update_entry_with_handle)(
        _In_ ebpf_core_map_t* map,
        _In_ const uint8_t* key,
        _In_ const uint8_t* value,
        uintptr_t value_handle,
        ebpf_map_option_t option);
    ebpf_result_t (*update_entry_per_cpu)(
        _In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option);
    ebpf_result_t (*delete_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*next_key)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* previous_key, _Out_ uint8_t* next_key);
} ebpf_map_function_table_t;

ebpf_map_function_table_t ebpf_map_function_tables[];

const ebpf_map_definition_in_memory_t*
ebpf_map_get_definition(_In_ const ebpf_map_t* map)
{
    return &map->ebpf_map_definition;
}

uint32_t
ebpf_map_get_effective_value_size(_In_ const ebpf_map_t* map)
{
    return map->original_value_size;
}

static ebpf_core_map_t*
_create_array_map_with_extra_value_size(
    size_t map_struct_size, _In_ const ebpf_map_definition_in_memory_t* map_definition, size_t extra_value_size)
{
    ebpf_result_t retval;
    size_t map_data_size = 0;
    ebpf_core_map_t* map = NULL;

    size_t actual_value_size;
    retval = ebpf_safe_size_t_add(map_definition->value_size, extra_value_size, &actual_value_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_safe_size_t_multiply(map_definition->max_entries, actual_value_size, &map_data_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    size_t full_map_size;
    retval = ebpf_safe_size_t_add(PAD_CACHE(map_struct_size), map_data_size, &full_map_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    // allocate
    map = ebpf_allocate_cache_aligned(full_map_size);
    if (map == NULL) {
        goto Done;
    }
    memset(map, 0, full_map_size);

    map->ebpf_map_definition = *map_definition;
    map->data = ((uint8_t*)map) + PAD_CACHE(map_struct_size);

Done:
    return map;
}

static ebpf_core_map_t*
_create_array_map(_In_ const ebpf_map_definition_in_memory_t* map_definition)
{
    return _create_array_map_with_extra_value_size(sizeof(ebpf_core_map_t), map_definition, 0);
}

static void
_delete_array_map(_In_ ebpf_core_map_t* map)
{
    ebpf_free_cache_aligned(map);
}

static uint8_t*
_find_array_map_entry_with_extra_value_size(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, int extra_value_size)
{
    uint32_t key_value;
    if (!map || !key)
        return NULL;

    key_value = *(uint32_t*)key;

    if (key_value >= map->ebpf_map_definition.max_entries)
        return NULL;

    // The following addition is safe since it was checked during map creation.
    size_t actual_value_size = ((size_t)map->ebpf_map_definition.value_size) + extra_value_size;

    return &map->data[key_value * actual_value_size];
}

static uint8_t*
_find_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    return _find_array_map_entry_with_extra_value_size(map, key, 0);
}

static ebpf_result_t
_update_array_map_entry(
    _In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_opt_ const uint8_t* data, ebpf_map_option_t option)
{
    uint32_t key_value;

    if (!map || !key || (option == EBPF_NOEXIST))
        return EBPF_INVALID_ARGUMENT;

    key_value = *(uint32_t*)key;

    if (key_value >= map->ebpf_map_definition.max_entries)
        return EBPF_INVALID_ARGUMENT;

    uint8_t* entry = &map->data[*key * map->ebpf_map_definition.value_size];
    if (data) {
        memcpy(entry, data, map->ebpf_map_definition.value_size);
    } else {
        memset(entry, 0, map->ebpf_map_definition.value_size);
    }
    return EBPF_SUCCESS;
}

static ebpf_result_t
_delete_array_map_entry_with_reference(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, bool with_reference)
{
    uint32_t key_value;
    if (!map || !key)
        return EBPF_INVALID_ARGUMENT;

    key_value = *(uint32_t*)key;

    if (key_value > map->ebpf_map_definition.max_entries)
        return EBPF_INVALID_ARGUMENT;

    uint8_t* entry = &map->data[key_value * map->ebpf_map_definition.value_size];
    ebpf_lock_state_t lock_state = ebpf_lock_lock(&map->lock);
    if (with_reference) {
        ebpf_object_t** object_pointer = (ebpf_object_t**)(entry + map->ebpf_map_definition.value_size);
        ebpf_object_release_reference(*object_pointer);
        *object_pointer = NULL;
    }
    memset(entry, 0, map->ebpf_map_definition.value_size);
    ebpf_lock_unlock(&map->lock, lock_state);
    return EBPF_SUCCESS;
}

static ebpf_result_t
_delete_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    return _delete_array_map_entry_with_reference(map, key, FALSE);
}

static ebpf_result_t
_next_array_map_key(_In_ ebpf_core_map_t* map, _In_ const uint8_t* previous_key, _Out_ uint8_t* next_key)
{
    uint32_t key_value;
    if (!map || !next_key)
        return EBPF_INVALID_ARGUMENT;

    if (previous_key) {
        key_value = *(uint32_t*)previous_key;
        key_value++;
    } else
        key_value = 0;

    if (key_value >= map->ebpf_map_definition.max_entries)
        return EBPF_NO_MORE_KEYS;

    *(uint32_t*)next_key = key_value;

    return EBPF_SUCCESS;
}

static ebpf_core_map_t*
_create_object_array_map(_In_ const ebpf_map_definition_in_memory_t* map_definition)
{
    return _create_array_map_with_extra_value_size(sizeof(ebpf_core_object_map_t), map_definition, sizeof(void*));
}

static void
_delete_object_array_map(_In_ ebpf_core_map_t* map)
{
    // The following addition is safe since it was checked during map creation.
    size_t actual_value_size = ((size_t)map->ebpf_map_definition.value_size) + sizeof(ebpf_object_t*);

    // Release all entry references.
    for (uint32_t i = 0; i < map->ebpf_map_definition.max_entries; i++) {
        uint8_t* entry = &map->data[i * actual_value_size];
        ebpf_object_t* object = *(ebpf_object_t**)(entry + map->ebpf_map_definition.value_size);
        ebpf_object_release_reference(object);
    }

    _delete_array_map(map);
}

static ebpf_result_t
_associate_program_with_prog_array_map(_In_ ebpf_core_map_t* map, _In_ const ebpf_program_t* program)
{
    ebpf_assert(map->ebpf_map_definition.type == BPF_MAP_TYPE_PROG_ARRAY);
    ebpf_core_object_map_t* program_array = (ebpf_core_object_map_t*)map;

    // Validate that the program type is
    // not in conflict with the map's program type.
    const ebpf_program_type_t* program_type = ebpf_program_type(program);
    ebpf_result_t result = EBPF_SUCCESS;

    ebpf_lock_state_t lock_state = ebpf_lock_lock(&map->lock);

    if (!program_array->is_program_type_set) {
        program_array->is_program_type_set = TRUE;
        program_array->program_type = *program_type;
    } else if (memcmp(&program_array->program_type, program_type, sizeof(*program_type)) != 0) {
        result = EBPF_INVALID_FD;
    }

    ebpf_lock_unlock(&map->lock, lock_state);

    return result;
}

static bool // Returns true if ok, false if not.
_check_value_type(_In_ const ebpf_core_map_t* outer_map, _In_ const ebpf_object_t* value_object)
{
    if (outer_map->ebpf_map_definition.type != BPF_MAP_TYPE_ARRAY_OF_MAPS &&
        outer_map->ebpf_map_definition.type != BPF_MAP_TYPE_HASH_OF_MAPS) {
        return true;
    }

    ebpf_core_map_t* template = outer_map->inner_map_template;
    const ebpf_map_t* value_map = (ebpf_map_t*)value_object;

    // TODO(discussion #460): what other map attributes need to match?
    bool allowed = (template != NULL) && (value_map->ebpf_map_definition.type == template->ebpf_map_definition.type);

    return allowed;
}

static ebpf_result_t
_update_array_map_entry_with_handle(
    _In_ ebpf_core_map_t* map,
    _In_ const uint8_t* key,
    ebpf_object_type_t value_type,
    _In_ const uint8_t* value,
    uintptr_t value_handle,
    ebpf_map_option_t option)
{
    if (!map || !key || !value)
        return EBPF_INVALID_ARGUMENT;

    // TODO(issue #396): support option.  This should be easy
    // once this function is removed.
    if (option != EBPF_ANY)
        return EBPF_INVALID_ARGUMENT;

    uint32_t index = *(uint32_t*)key;

    if (index >= map->ebpf_map_definition.max_entries)
        return EBPF_INVALID_ARGUMENT;

    // Convert value handle to an object pointer.
    ebpf_object_t* value_object;
    int return_value = ebpf_reference_object_by_handle(value_handle, value_type, &value_object);
    if (return_value != EBPF_SUCCESS)
        return return_value;

    // The following addition is safe since it was checked during map creation.
    size_t actual_value_size = ((size_t)map->ebpf_map_definition.value_size) + sizeof(struct _ebpf_object*);

    ebpf_result_t result = EBPF_SUCCESS;

    const ebpf_program_type_t* value_program_type =
        (value_object->get_program_type) ? value_object->get_program_type(value_object) : NULL;

    ebpf_lock_state_t lock_state = ebpf_lock_lock(&map->lock);

    if (value_type == EBPF_OBJECT_MAP) {
        // Validate that the value is of the correct type.
        if (!_check_value_type(map, value_object)) {
            ebpf_object_release_reference(value_object);
            result = EBPF_INVALID_FD;
            goto Done;
        }
    }

    // Validate that the value's program type (if any) is
    // not in conflict with the map's program type.
    if (value_program_type) {
        ebpf_core_object_map_t* map_of_objects = (ebpf_core_object_map_t*)map;
        if (!map_of_objects->is_program_type_set) {
            map_of_objects->is_program_type_set = TRUE;
            map_of_objects->program_type = *value_program_type;
        } else if (memcmp(&map_of_objects->program_type, value_program_type, sizeof(*value_program_type)) != 0) {
            ebpf_object_release_reference(value_object);
            result = EBPF_INVALID_FD;
            goto Done;
        }
    }

    // Store the literal value.
    uint8_t* entry = &map->data[*key * actual_value_size];
    if (value) {
        memcpy(entry, value, map->ebpf_map_definition.value_size);
    } else {
        memset(entry, 0, map->ebpf_map_definition.value_size);
    }

    // Store object pointer after the value.
    memcpy(entry + map->ebpf_map_definition.value_size, &value_object, sizeof(void*));

Done:
    ebpf_lock_unlock(&map->lock, lock_state);

    return result;
}

static ebpf_result_t
_update_prog_array_map_entry_with_handle(
    _In_ ebpf_core_map_t* map,
    _In_ const uint8_t* key,
    _In_ const uint8_t* value,
    uintptr_t value_handle,
    ebpf_map_option_t option)
{
    return _update_array_map_entry_with_handle(map, key, EBPF_OBJECT_PROGRAM, value, value_handle, option);
}

static ebpf_result_t
_update_map_array_map_entry_with_handle(
    _In_ ebpf_core_map_t* map,
    _In_ const uint8_t* key,
    _In_ const uint8_t* value,
    uintptr_t value_handle,
    ebpf_map_option_t option)
{
    return _update_array_map_entry_with_handle(map, key, EBPF_OBJECT_MAP, value, value_handle, option);
}

static ebpf_result_t
_delete_object_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    return _delete_array_map_entry_with_reference(map, key, TRUE);
}

/**
 * @brief Get an object from a map entry that holds objects, such
 * as a program array or array of maps.  The object returned holds a
 * reference that the caller is responsible for releasing.
 *
 * @param[in] map Array map to search.
 * @param[in] key Pointer to the key to search for.
 * @returns Object pointer, or NULL if none.
 */
static _Ret_maybenull_ ebpf_object_t*
_get_object_from_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    uint32_t index = *(uint32_t*)key;

    // We need to take a lock here to make sure we can
    // safely reference the object when another thread
    // might be trying to delete the entry we find.
    ebpf_lock_state_t lock_state = ebpf_lock_lock(&map->lock);

    ebpf_object_t* object = NULL;
    uint8_t* value = _find_array_map_entry_with_extra_value_size(map, (uint8_t*)&index, sizeof(ebpf_object_t*));
    if (value != NULL) {
        // The object pointer is stored after the fd integer value.
        object = *(ebpf_object_t**)(value + sizeof(uint32_t));
        if (object) {
            ebpf_object_acquire_reference(object);
        }
    }

    ebpf_lock_unlock(&map->lock, lock_state);

    return object;
}

static ebpf_core_map_t*
_create_hash_map_with_extra_value_size(
    size_t map_struct_size, _In_ const ebpf_map_definition_in_memory_t* map_definition, size_t extra_value_size)
{
    ebpf_result_t retval;
    ebpf_core_map_t* map = NULL;

    size_t actual_value_size;
    retval = ebpf_safe_size_t_add(map_definition->value_size, extra_value_size, &actual_value_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    map = ebpf_allocate(map_struct_size);
    if (map == NULL) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    map->ebpf_map_definition = *map_definition;
    map->data = NULL;

    // Note:
    // ebpf_hash_table_t doesn't require synchronization as long as allocations
    // are performed using the epoch allocator.
    retval = ebpf_hash_table_create(
        (ebpf_hash_table_t**)&map->data,
        ebpf_epoch_allocate,
        ebpf_epoch_free,
        map->ebpf_map_definition.key_size,
        actual_value_size,
        map->ebpf_map_definition.max_entries,
        NULL);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = EBPF_SUCCESS;

Done:
    if (retval != EBPF_SUCCESS) {
        if (map && map->data) {
            ebpf_hash_table_destroy((ebpf_hash_table_t*)map->data);
        }
        ebpf_free(map);
        map = NULL;
    }
    return map;
}

static ebpf_core_map_t*
_create_hash_map(_In_ const ebpf_map_definition_in_memory_t* map_definition)
{
    return _create_hash_map_with_extra_value_size(sizeof(ebpf_core_map_t), map_definition, 0);
}

static ebpf_core_map_t*
_create_object_hash_map(_In_ const ebpf_map_definition_in_memory_t* map_definition)
{
    return _create_hash_map_with_extra_value_size(sizeof(ebpf_core_object_map_t), map_definition, sizeof(void*));
}

static void
_delete_hash_map(_In_ ebpf_core_map_t* map)
{
    ebpf_hash_table_destroy((ebpf_hash_table_t*)map->data);
    ebpf_free(map);
}

static void
_delete_object_hash_map(_In_ ebpf_core_map_t* map)
{
    // Release all entry references.
    uint8_t* next_key;
    for (uint8_t* previous_key = NULL;; previous_key = next_key) {
        uint8_t* value;
        ebpf_result_t result =
            ebpf_hash_table_next_key_pointer_and_value((ebpf_hash_table_t*)map->data, NULL, &next_key, &value);
        if (result != EBPF_SUCCESS) {
            break;
        }
        ebpf_object_t* object = *(ebpf_object_t**)(value + map->ebpf_map_definition.value_size);
        ebpf_object_release_reference(object);
    }

    _delete_hash_map(map);
}

static uint8_t*
_find_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    uint8_t* value = NULL;
    if (!map || !key)
        return NULL;

    if (ebpf_hash_table_find((ebpf_hash_table_t*)map->data, key, &value) != EBPF_SUCCESS) {
        value = NULL;
    }

    return value;
}

/**
 * @brief Get an object from a map entry that holds objects, such
 * as a hash of maps.  The object returned holds a
 * reference that the caller is responsible for releasing.
 *
 * @param[in] map Hash map to search.
 * @param[in] key Pointer to the key to search for.
 * @returns Object pointer, or NULL if none.
 */
static _Ret_maybenull_ ebpf_object_t*
_get_object_from_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    // We need to take a lock here to make sure we can
    // safely reference the object when another thread
    // might be trying to delete the entry we find.
    ebpf_lock_state_t lock_state = ebpf_lock_lock(&map->lock);

    ebpf_object_t* object = NULL;
    uint8_t* value = _find_hash_map_entry(map, key);
    if (value != NULL) {
        // The object pointer is stored after the fd integer value.
        object = *(ebpf_object_t**)(value + sizeof(uint32_t));
        if (object) {
            ebpf_object_acquire_reference(object);
        }
    }

    ebpf_lock_unlock(&map->lock, lock_state);

    return object;
}

static ebpf_result_t
_update_hash_map_entry(
    _In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_opt_ const uint8_t* data, ebpf_map_option_t option)
{
    ebpf_result_t result;
    size_t entry_count = 0;
    uint8_t* value;
    ebpf_hash_table_operations_t hash_table_operation;

    if (!map || !key)
        return EBPF_INVALID_ARGUMENT;

    switch (option) {
    case EBPF_ANY:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_ANY;
        break;
    case EBPF_NOEXIST:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_INSERT;
        break;
    case EBPF_EXIST:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_REPLACE;
        break;
    default:
        return EBPF_INVALID_ARGUMENT;
    }

    entry_count = ebpf_hash_table_key_count((ebpf_hash_table_t*)map->data);

    if ((entry_count == map->ebpf_map_definition.max_entries) &&
        (ebpf_hash_table_find((ebpf_hash_table_t*)map->data, key, &value) != EBPF_SUCCESS))
        result = EBPF_INVALID_ARGUMENT;
    else
        result = ebpf_hash_table_update((ebpf_hash_table_t*)map->data, key, data, NULL, hash_table_operation);

    return result;
}

static ebpf_result_t
_update_hash_map_entry_with_handle(
    _In_ ebpf_core_map_t* map,
    _In_ const uint8_t* key,
    ebpf_object_type_t value_type,
    _In_ const uint8_t* new_value,
    uintptr_t value_handle,
    ebpf_map_option_t option)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t lock_state;
    size_t entry_count = 0;
    if (!map || !key || !new_value)
        return EBPF_INVALID_ARGUMENT;

    ebpf_hash_table_operations_t hash_table_operation;
    switch (option) {
    case EBPF_ANY:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_ANY;
        break;
    case EBPF_NOEXIST:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_INSERT;
        break;
    case EBPF_EXIST:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_REPLACE;
        break;
    default:
        return EBPF_INVALID_ARGUMENT;
    }

    // Convert value handle to an object pointer.
    struct _ebpf_object* object;
    int return_value = ebpf_reference_object_by_handle(value_handle, value_type, &object);
    if (return_value != EBPF_SUCCESS)
        return return_value;

    // Validate that the object's program type is
    // not in conflict with the map's program type.
    const ebpf_program_type_t* program_type = (object->get_program_type) ? object->get_program_type(object) : NULL;
    ebpf_core_object_map_t* object_map = (ebpf_core_object_map_t*)map;

    lock_state = ebpf_lock_lock(&map->lock);
    entry_count = ebpf_hash_table_key_count((ebpf_hash_table_t*)map->data);

    uint8_t* old_value;
    if ((entry_count == map->ebpf_map_definition.max_entries) &&
        (ebpf_hash_table_find((ebpf_hash_table_t*)map->data, key, &old_value) != EBPF_SUCCESS))
        result = EBPF_INVALID_ARGUMENT;
    else {
        if (program_type != NULL) {
            if (!object_map->is_program_type_set) {
                object_map->is_program_type_set = TRUE;
                object_map->program_type = *program_type;
            } else if (memcmp(&object_map->program_type, program_type, sizeof(*program_type)) != 0) {
                ebpf_object_release_reference((ebpf_object_t*)object);
                result = EBPF_INVALID_FD;
                goto Done;
            }
        }

        // Store the literal value and the object pointer.
        result = ebpf_hash_table_update(
            (ebpf_hash_table_t*)map->data, key, new_value, (uint8_t*)&object, hash_table_operation);
    }

Done:
    ebpf_lock_unlock(&map->lock, lock_state);
    return result;
}

static ebpf_result_t
_update_map_hash_map_entry_with_handle(
    _In_ ebpf_core_map_t* map,
    _In_ const uint8_t* key,
    _In_ const uint8_t* value,
    uintptr_t value_handle,
    ebpf_map_option_t option)
{
    return _update_hash_map_entry_with_handle(map, key, EBPF_OBJECT_MAP, value, value_handle, option);
}

static ebpf_result_t
_delete_hash_map_entry_with_reference(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, bool with_reference)
{
    ebpf_result_t result;
    if (!map || !key)
        return EBPF_INVALID_ARGUMENT;

    if (with_reference) {
        uint8_t* value = NULL;
        if (ebpf_hash_table_find((ebpf_hash_table_t*)map->data, key, &value) == EBPF_SUCCESS) {
            ebpf_object_t** object_pointer = (ebpf_object_t**)(value + map->ebpf_map_definition.value_size);
            ebpf_object_release_reference(*object_pointer);
            *object_pointer = NULL;
        }
    }
    result = ebpf_hash_table_delete((ebpf_hash_table_t*)map->data, key);
    return result;
}

static ebpf_result_t
_delete_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    return _delete_hash_map_entry_with_reference(map, key, FALSE);
}

static ebpf_result_t
_delete_object_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    return _delete_hash_map_entry_with_reference(map, key, TRUE);
}

static ebpf_result_t
_next_hash_map_key(_In_ ebpf_core_map_t* map, _In_ const uint8_t* previous_key, _Out_ uint8_t* next_key)
{
    ebpf_result_t result;
    if (!map || !next_key)
        return EBPF_INVALID_ARGUMENT;

    result = ebpf_hash_table_next_key((ebpf_hash_table_t*)map->data, previous_key, next_key);
    return result;
}

static ebpf_result_t
_ebpf_adjust_value_pointer(_In_ ebpf_map_t* map, _Inout_ uint8_t** value)
{
    uint32_t current_cpu;
    uint32_t max_cpu = map->ebpf_map_definition.value_size / PAD_CACHE(map->original_value_size);
    switch (map->ebpf_map_definition.type) {
    case BPF_MAP_TYPE_PERCPU_ARRAY:
    case BPF_MAP_TYPE_PERCPU_HASH:
        break;
    default:
        return EBPF_SUCCESS;
    }
    current_cpu = ebpf_get_current_cpu();

    if (current_cpu > max_cpu) {
        return EBPF_INVALID_ARGUMENT;
    }
    (*value) += PAD_CACHE((size_t)map->original_value_size) * current_cpu;
    return EBPF_SUCCESS;
}

/**
 * @brief Insert the supplied value into the per-cpu value buffer of the map.
 * If the map doesn't contain an existing value, create a new all-zero value,
 * insert it, then set the per-cpu value. Note: This races with updates to the
 * value buffer from user mode.
 *
 * @param[in] map Map to update.
 * @param[in] key Key to search for.
 * @param[in] value Value to insert.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate resources for this
 *  entry.
 * @retval EBPF_INVALID_ARGUMENT Unable to perform this operation due to
 * current CPU > allocated value buffer size.
 */
ebpf_result_t
_update_entry_per_cpu(
    _In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option)
{
    uint8_t* target = ebpf_map_function_tables[map->ebpf_map_definition.type].find_entry(map, key);
    if (!target) {
        ebpf_result_t return_value =
            ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry(map, key, NULL, option);
        if (return_value != EBPF_SUCCESS) {
            return return_value;
        }
        target = ebpf_map_function_tables[map->ebpf_map_definition.type].find_entry(map, key);
        if (!target) {
            return EBPF_NO_MEMORY;
        }
    }
    if (_ebpf_adjust_value_pointer(map, &target) != EBPF_SUCCESS) {
        return EBPF_INVALID_ARGUMENT;
    }

    memcpy(target, value, ebpf_map_get_effective_value_size(map));
    return EBPF_SUCCESS;
}

ebpf_map_function_table_t ebpf_map_function_tables[] = {
    {// BPF_MAP_TYPE_UNSPECIFIED
     NULL},
    {// BPF_MAP_TYPE_HASH
     _create_hash_map,
     _delete_hash_map,
     NULL,
     _find_hash_map_entry,
     NULL,
     _update_hash_map_entry,
     NULL,
     NULL,
     _delete_hash_map_entry,
     _next_hash_map_key},
    {// BPF_MAP_TYPE_ARRAY
     _create_array_map,
     _delete_array_map,
     NULL,
     _find_array_map_entry,
     NULL,
     _update_array_map_entry,
     NULL,
     NULL,
     _delete_array_map_entry,
     _next_array_map_key},
    {// BPF_MAP_TYPE_PROG_ARRAY
     _create_object_array_map,
     _delete_object_array_map,
     _associate_program_with_prog_array_map,
     _find_array_map_entry,
     _get_object_from_array_map_entry,
     NULL,
     _update_prog_array_map_entry_with_handle,
     NULL,
     _delete_object_array_map_entry,
     _next_array_map_key},
    {// BPF_MAP_TYPE_PERCPU_HASH
     _create_hash_map,
     _delete_hash_map,
     NULL,
     _find_hash_map_entry,
     NULL,
     _update_hash_map_entry,
     NULL,
     _update_entry_per_cpu,
     _delete_hash_map_entry,
     _next_hash_map_key},
    {// BPF_MAP_TYPE_PERCPU_ARRAY
     _create_array_map,
     _delete_array_map,
     NULL,
     _find_array_map_entry,
     NULL,
     _update_array_map_entry,
     NULL,
     _update_entry_per_cpu,
     _delete_array_map_entry,
     _next_array_map_key},
    {// BPF_MAP_TYPE_HASH_OF_MAPS
     _create_object_hash_map,
     _delete_object_hash_map,
     NULL,
     _find_hash_map_entry,
     _get_object_from_hash_map_entry,
     NULL,
     _update_map_hash_map_entry_with_handle,
     NULL,
     _delete_object_hash_map_entry,
     _next_array_map_key},
    {// BPF_MAP_TYPE_ARRAY_OF_MAPS
     _create_object_array_map,
     _delete_object_array_map,
     NULL,
     _find_array_map_entry,
     _get_object_from_array_map_entry,
     NULL,
     _update_map_array_map_entry_with_handle,
     NULL,
     _delete_object_array_map_entry,
     _next_array_map_key},
};

static void
_ebpf_map_delete(_In_ ebpf_object_t* object)
{
    ebpf_map_t* map = (ebpf_map_t*)object;

    if (map->inner_map_template != NULL) {
        ebpf_object_release_reference(&map->inner_map_template->object);
    }
    ebpf_free(map->name.value);
    ebpf_map_function_tables[map->ebpf_map_definition.type].delete_map(map);
}

ebpf_result_t
ebpf_map_create(
    _In_ const ebpf_utf8_string_t* map_name,
    _In_ const ebpf_map_definition_in_memory_t* ebpf_map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_map_t** ebpf_map)
{
    ebpf_map_t* local_map = NULL;
    ebpf_object_t* inner_map_template_object = NULL;
    ebpf_map_type_t type = ebpf_map_definition->type;
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t cpu_count;
    cpu_count = ebpf_get_cpu_count();
    ebpf_map_definition_in_memory_t local_map_definition = *ebpf_map_definition;
    switch (local_map_definition.type) {
    case BPF_MAP_TYPE_PERCPU_HASH:
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        local_map_definition.value_size = cpu_count * PAD_CACHE(local_map_definition.value_size);
        break;
    default:
        break;
    }

    if (type >= EBPF_COUNT_OF(ebpf_map_function_tables)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (!ebpf_map_function_tables[type].create_map) {
        result = EBPF_OPERATION_NOT_SUPPORTED;
        goto Exit;
    }

    if (local_map_definition.size != sizeof(local_map_definition)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (inner_map_handle != (ebpf_handle_t)-1) {
        // Convert value handle to an object pointer.
        result = ebpf_reference_object_by_handle(inner_map_handle, EBPF_OBJECT_MAP, &inner_map_template_object);
        if (result != EBPF_SUCCESS)
            goto Exit;
    }

    local_map = ebpf_map_function_tables[type].create_map(&local_map_definition);
    if (!local_map) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    local_map->original_value_size = ebpf_map_definition->value_size;

    result = ebpf_duplicate_utf8_string(&local_map->name, map_name);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    ebpf_map_function_table_t* table = &ebpf_map_function_tables[local_map->ebpf_map_definition.type];
    ebpf_object_get_program_type_t get_program_type = (table->get_object_from_entry) ? _get_map_program_type : NULL;
    result = ebpf_object_initialize(&local_map->object, EBPF_OBJECT_MAP, _ebpf_map_delete, get_program_type);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    local_map->inner_map_template = (ebpf_map_t*)inner_map_template_object;
    *ebpf_map = local_map;

Exit:
    if (result != EBPF_SUCCESS) {
        if (local_map) {
            ebpf_object_release_reference(inner_map_template_object);
            ebpf_free(local_map->name.value);
            ebpf_free(local_map);
        }
    }
    return result;
}

ebpf_result_t
ebpf_map_find_entry(
    _In_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    size_t value_size,
    _Out_writes_(value_size) uint8_t* value,
    int flags)
{
    uint8_t* return_value = NULL;
    if (!(flags & EBPF_MAP_FLAG_HELPER) && (key_size != map->ebpf_map_definition.key_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (!(flags & EBPF_MAP_FLAG_HELPER) && (value_size != map->ebpf_map_definition.value_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_map_type_t type = map->ebpf_map_definition.type;
    if ((flags & EBPF_MAP_FLAG_HELPER) && (ebpf_map_function_tables[type].get_object_from_entry != NULL)) {

        // Disallow reads to prog array maps from this helper call for now.
        if (type == BPF_MAP_TYPE_PROG_ARRAY) {
            return EBPF_INVALID_ARGUMENT;
        }

        ebpf_object_t* object = ebpf_map_function_tables[type].get_object_from_entry(map, key);

        // Release the extra reference obtained.
        // REVIEW: is this safe?
        if (object) {
            ebpf_object_release_reference(object);
            return_value = (uint8_t*)object;
        }
    } else {
        return_value = ebpf_map_function_tables[map->ebpf_map_definition.type].find_entry(map, key);
    }
    if (return_value == NULL) {
        return EBPF_OBJECT_NOT_FOUND;
    }

    if (flags & EBPF_MAP_FLAG_HELPER) {
        if (_ebpf_adjust_value_pointer(map, &return_value) != EBPF_SUCCESS) {
            return EBPF_INVALID_ARGUMENT;
        }

        *(uint8_t**)value = return_value;
    } else {
        memcpy(value, return_value, map->ebpf_map_definition.value_size);
    }
    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_map_associate_program(_In_ ebpf_map_t* map, _In_ const ebpf_program_t* program)
{
    if (ebpf_map_function_tables[map->ebpf_map_definition.type].associate_program)
        return ebpf_map_function_tables[map->ebpf_map_definition.type].associate_program(map, program);
    return EBPF_SUCCESS;
}

_Ret_maybenull_ ebpf_program_t*
ebpf_map_get_program_from_entry(_In_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key)
{
    if (key_size != map->ebpf_map_definition.key_size) {
        return NULL;
    }
    ebpf_map_type_t type = map->ebpf_map_definition.type;
    if (type != BPF_MAP_TYPE_PROG_ARRAY) {
        return NULL;
    }

    if (ebpf_map_function_tables[type].get_object_from_entry == NULL) {
        return NULL;
    }
    return (ebpf_program_t*)ebpf_map_function_tables[type].get_object_from_entry(map, key);
}

ebpf_result_t
ebpf_map_update_entry(
    _In_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    ebpf_map_option_t option,
    int flags)
{
    if (!(flags & EBPF_MAP_FLAG_HELPER) && (key_size != map->ebpf_map_definition.key_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (!(flags & EBPF_MAP_FLAG_HELPER) && (value_size != map->ebpf_map_definition.value_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    if ((ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry == NULL) ||
        (ebpf_map_function_tables[map->ebpf_map_definition.type].find_entry == NULL)) {
        return EBPF_INVALID_ARGUMENT;
    }

    if ((flags & EBPF_MAP_FLAG_HELPER) &&
        ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry_per_cpu) {
        return ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry_per_cpu(map, key, value, option);
    } else {
        return ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry(map, key, value, option);
    }
}

ebpf_result_t
ebpf_map_update_entry_with_handle(
    _In_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    uintptr_t value_handle,
    ebpf_map_option_t option)
{
    if (key_size != map->ebpf_map_definition.key_size) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (value_size != map->ebpf_map_definition.value_size) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry_with_handle == NULL) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry_with_handle(
        map, key, value, value_handle, option);
}

ebpf_result_t
ebpf_map_delete_entry(_In_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, int flags)
{
    if (!(flags & EBPF_MAP_FLAG_HELPER) && (key_size != map->ebpf_map_definition.key_size)) {
        return EBPF_INVALID_ARGUMENT;
    }
    return ebpf_map_function_tables[map->ebpf_map_definition.type].delete_entry(map, key);
}

ebpf_result_t
ebpf_map_next_key(
    _In_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key)
{
    if (key_size != map->ebpf_map_definition.key_size) {
        return EBPF_INVALID_ARGUMENT;
    }
    return ebpf_map_function_tables[map->ebpf_map_definition.type].next_key(map, previous_key, next_key);
}
