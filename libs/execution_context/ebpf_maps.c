// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"

typedef struct _ebpf_core_map
{
    ebpf_object_t object;
    struct _ebpf_map_definition ebpf_map_definition;
    ebpf_lock_t lock;
    uint8_t* data;
} ebpf_core_map_t;

typedef struct _ebpf_map_function_table
{
    ebpf_core_map_t* (*create_map)(_In_ const ebpf_map_definition_t* map_definition);
    void (*delete_map)(_In_ ebpf_core_map_t* map);
    uint8_t* (*find_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_object_t* (*get_object_from_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*update_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value);
    ebpf_result_t (*update_entry_with_handle)(
        _In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, uintptr_t value_handle);
    ebpf_result_t (*delete_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*next_key)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* previous_key, _Out_ uint8_t* next_key);
} ebpf_map_function_table_t;

const ebpf_map_definition_t*
ebpf_map_get_definition(_In_ const ebpf_map_t* map)
{
    return &map->ebpf_map_definition;
}

static ebpf_core_map_t*
_create_array_map_with_extra_value_size(_In_ const ebpf_map_definition_t* map_definition, size_t extra_value_size)
{
    ebpf_result_t retval;
    size_t map_entry_size = sizeof(ebpf_core_map_t);
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

    retval = ebpf_safe_size_t_multiply(map_data_size, map_entry_size, &map_entry_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    // allocate
    map = ebpf_allocate(map_entry_size);
    if (map == NULL) {
        goto Done;
    }
    memset(map, 0, map_entry_size);

    map->ebpf_map_definition = *map_definition;
    map->data = (uint8_t*)(map + 1);

Done:
    return map;
}

static ebpf_core_map_t*
_create_array_map(_In_ const ebpf_map_definition_t* map_definition)
{
    return _create_array_map_with_extra_value_size(map_definition, 0);
}

static void
_delete_array_map(_In_ ebpf_core_map_t* map)
{
    ebpf_free(map);
}

static uint8_t*
_find_array_map_entry_with_extra_value_size(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, int extra_value_size)
{
    uint32_t key_value;
    if (!map || !key)
        return NULL;

    key_value = *(uint32_t*)key;

    if (key_value > map->ebpf_map_definition.max_entries)
        return NULL;

    // The following addition is safe since it was checked during map creation.
    size_t actual_value_size = map->ebpf_map_definition.value_size + extra_value_size;

    return &map->data[key_value * actual_value_size];
}

static uint8_t*
_find_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    return _find_array_map_entry_with_extra_value_size(map, key, 0);
}

static ebpf_result_t
_update_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* data)
{
    uint32_t key_value;
    if (!map || !key)
        return EBPF_INVALID_ARGUMENT;

    key_value = *(uint32_t*)key;

    if (key_value >= map->ebpf_map_definition.max_entries)
        return EBPF_INVALID_ARGUMENT;

    uint8_t* entry = &map->data[*key * map->ebpf_map_definition.value_size];
    memcpy(entry, data, map->ebpf_map_definition.value_size);
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
        return EBPF_KEY_NOT_FOUND;

    uint8_t* entry = &map->data[key_value * map->ebpf_map_definition.value_size];
    if (with_reference) {
        ebpf_object_t** object_pointer = (ebpf_object_t**)(entry + map->ebpf_map_definition.value_size);
        ebpf_object_release_reference(*object_pointer);
        *object_pointer = NULL;
    }
    memset(entry, 0, map->ebpf_map_definition.value_size);
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
_create_prog_array_map(_In_ const ebpf_map_definition_t* map_definition)
{
    return _create_array_map_with_extra_value_size(map_definition, sizeof(struct _ebpf_program*));
}

static void
_delete_array_map_with_references(_In_ ebpf_core_map_t* map)
{
    // The following addition is safe since it was checked during map creation.
    size_t actual_value_size = map->ebpf_map_definition.value_size + sizeof(ebpf_object_t*);

    // Release all entry references.
    for (uint32_t i = 0; i < map->ebpf_map_definition.max_entries; i++) {
        uint8_t* entry = &map->data[i * actual_value_size];
        ebpf_object_t* object = *(ebpf_object_t**)(entry + map->ebpf_map_definition.value_size);
        ebpf_object_release_reference(object);
    }

    ebpf_free(map);
}

static ebpf_result_t
_update_prog_array_map_entry_with_handle(
    _In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, uintptr_t value_handle)
{
    if (!map || !key)
        return EBPF_INVALID_ARGUMENT;

    uint32_t index = *(uint32_t*)key;

    if (index >= map->ebpf_map_definition.max_entries)
        return EBPF_INVALID_ARGUMENT;

    // Convert value handle to a program pointer.
    struct _ebpf_program* program;
    int return_value = ebpf_reference_object_by_handle(value_handle, EBPF_OBJECT_PROGRAM, (ebpf_object_t**)&program);
    if (return_value != EBPF_SUCCESS)
        return return_value;

    // The following addition is safe since it was checked during map creation.
    size_t actual_value_size = map->ebpf_map_definition.value_size + sizeof(struct _ebpf_program*);

    // TODO(issue #344): validate that the program type is
    // not in conflict with the map's program type.

    // Store the literal value.
    uint8_t* entry = &map->data[*key * actual_value_size];
    memcpy(entry, value, map->ebpf_map_definition.value_size);

    // Store program pointer after the value.
    memcpy(entry + map->ebpf_map_definition.value_size, &program, sizeof(program));

    return EBPF_SUCCESS;
}

static ebpf_result_t
_delete_prog_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    return _delete_array_map_entry_with_reference(map, key, TRUE);
}

/**
 * @brief Get an object from a map entry that holds objects, such
 * as a program array or map of maps.  The object returned holds a
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
_create_hash_map(_In_ const ebpf_map_definition_t* map_definition)
{
    ebpf_result_t retval;
    size_t map_size = sizeof(ebpf_core_map_t);
    ebpf_core_map_t* map = NULL;

    map = ebpf_allocate(map_size);
    if (map == NULL) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    map->ebpf_map_definition = *map_definition;
    map->data = NULL;

    retval = ebpf_hash_table_create(
        (ebpf_hash_table_t**)&map->data,
        ebpf_epoch_allocate,
        ebpf_epoch_free,
        map->ebpf_map_definition.key_size,
        map->ebpf_map_definition.value_size,
        NULL);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    ebpf_lock_create(&map->lock);
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

static void
_delete_hash_map(_In_ ebpf_core_map_t* map)
{
    ebpf_lock_destroy(&map->lock);
    ebpf_hash_table_destroy((ebpf_hash_table_t*)map->data);
    ebpf_free(map);
}

static uint8_t*
_find_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    ebpf_lock_state_t lock_state;
    uint8_t* value = NULL;
    if (!map || !key)
        return NULL;

    lock_state = ebpf_lock_lock(&map->lock);
    if (ebpf_hash_table_find((ebpf_hash_table_t*)map->data, key, &value) != EBPF_SUCCESS) {
        value = NULL;
    }
    ebpf_lock_unlock(&map->lock, lock_state);

    return value;
}

static ebpf_result_t
_update_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* data)
{
    ebpf_result_t result;
    ebpf_lock_state_t lock_state;
    size_t entry_count = 0;
    uint8_t* value;
    if (!map || !key || !data)
        return EBPF_INVALID_ARGUMENT;

    lock_state = ebpf_lock_lock(&map->lock);
    entry_count = ebpf_hash_table_key_count((ebpf_hash_table_t*)map->data);

    if ((entry_count == map->ebpf_map_definition.max_entries) &&
        (ebpf_hash_table_find((ebpf_hash_table_t*)map->data, key, &value) != EBPF_SUCCESS))
        result = EBPF_INVALID_ARGUMENT;
    else
        result = ebpf_hash_table_update((ebpf_hash_table_t*)map->data, key, data);
    ebpf_lock_unlock(&map->lock, lock_state);
    return result;
}

static ebpf_result_t
_delete_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    ebpf_result_t result;
    ebpf_lock_state_t lock_state;
    if (!map || !key)
        return EBPF_INVALID_ARGUMENT;

    lock_state = ebpf_lock_lock(&map->lock);
    result = ebpf_hash_table_delete((ebpf_hash_table_t*)map->data, key);
    ebpf_lock_unlock(&map->lock, lock_state);
    return result;
}

static ebpf_result_t
_next_hash_map_key(_In_ ebpf_core_map_t* map, _In_ const uint8_t* previous_key, _Out_ uint8_t* next_key)
{
    ebpf_result_t result;
    ebpf_lock_state_t lock_state;
    if (!map || !next_key)
        return EBPF_INVALID_ARGUMENT;

    lock_state = ebpf_lock_lock(&map->lock);
    result = ebpf_hash_table_next_key((ebpf_hash_table_t*)map->data, previous_key, next_key);
    ebpf_lock_unlock(&map->lock, lock_state);
    return result;
}

ebpf_map_function_table_t ebpf_map_function_tables[] = {
    {// BPF_MAP_TYPE_UNSPECIFIED
     NULL},
    {// BPF_MAP_TYPE_HASH
     _create_hash_map,
     _delete_hash_map,
     _find_hash_map_entry,
     NULL,
     _update_hash_map_entry,
     NULL,
     _delete_hash_map_entry,
     _next_hash_map_key},
    {// BPF_MAP_TYPE_ARRAY
     _create_array_map,
     _delete_array_map,
     _find_array_map_entry,
     NULL,
     _update_array_map_entry,
     NULL,
     _delete_array_map_entry,
     _next_array_map_key},
    {// BPF_MAP_TYPE_PROG_ARRAY
     _create_prog_array_map,
     _delete_array_map_with_references,
     _find_array_map_entry,
     _get_object_from_array_map_entry,
     NULL,
     _update_prog_array_map_entry_with_handle,
     _delete_prog_array_map_entry,
     _next_array_map_key},
};

ebpf_result_t
ebpf_map_create(_In_ const ebpf_map_definition_t* ebpf_map_definition, _Outptr_ ebpf_map_t** ebpf_map)
{
    ebpf_map_t* local_map = NULL;
    size_t type = ebpf_map_definition->type;

    if (ebpf_map_definition->type >= EBPF_COUNT_OF(ebpf_map_function_tables))
        return EBPF_INVALID_ARGUMENT;

    if (!ebpf_map_function_tables[type].create_map)
        return EBPF_OPERATION_NOT_SUPPORTED;

    local_map = ebpf_map_function_tables[type].create_map(ebpf_map_definition);
    if (!local_map)
        return EBPF_NO_MEMORY;

    ebpf_object_initialize(
        &local_map->object,
        EBPF_OBJECT_MAP,
        (ebpf_free_object_t)ebpf_map_function_tables[local_map->ebpf_map_definition.type].delete_map);

    *ebpf_map = local_map;

    return EBPF_SUCCESS;
}

uint8_t*
ebpf_map_find_entry(_In_ ebpf_map_t* map, _In_ const uint8_t* key, int is_helper)
{
    // Disallow reads to prog array maps from this helper call for now.
    if (is_helper && map->ebpf_map_definition.type == BPF_MAP_TYPE_PROG_ARRAY) {
        return NULL;
    }

    return ebpf_map_function_tables[map->ebpf_map_definition.type].find_entry(map, key);
}

_Ret_maybenull_ ebpf_program_t*
ebpf_map_get_program_from_entry(_In_ ebpf_map_t* map, _In_ const uint8_t* key, size_t key_size)
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
ebpf_map_update_entry(_In_ ebpf_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value)
{
    if (ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }
    return ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry(map, key, value);
}

ebpf_result_t
ebpf_map_update_entry_with_handle(
    _In_ ebpf_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, uintptr_t value_handle)
{
    if (ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry_with_handle == NULL) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry_with_handle(
        map, key, value, value_handle);
}

ebpf_result_t
ebpf_map_delete_entry(_In_ ebpf_map_t* map, _In_ const uint8_t* key)
{
    return ebpf_map_function_tables[map->ebpf_map_definition.type].delete_entry(map, key);
}

ebpf_result_t
ebpf_map_next_key(_In_ ebpf_map_t* map, _In_opt_ const uint8_t* previous_key, _Out_ uint8_t* next_key)
{
    return ebpf_map_function_tables[map->ebpf_map_definition.type].next_key(map, previous_key, next_key);
}
