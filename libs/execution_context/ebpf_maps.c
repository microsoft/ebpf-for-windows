// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"

#define PAD16(X) ((X + 15) & ~15)

typedef struct _ebpf_core_map
{
    ebpf_object_t object;
    ebpf_utf8_string_t name;
    struct _ebpf_map_definition ebpf_map_definition;
    ebpf_lock_t lock;
    uint32_t original_value_size;
    uint8_t* data;
} ebpf_core_map_t;

typedef struct _ebpf_program_array_map
{
    ebpf_core_map_t core_map;
    bool is_program_type_set;
    ebpf_program_type_t program_type;
} ebpf_program_array_map_t;

typedef struct _ebpf_map_function_table
{
    ebpf_core_map_t* (*create_map)(_In_ const ebpf_map_definition_t* map_definition);
    void (*delete_map)(_In_ ebpf_core_map_t* map);
    ebpf_result_t (*associate_program)(_In_ ebpf_map_t* map, _In_ const ebpf_program_t* program);
    uint8_t* (*find_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_object_t* (*get_object_from_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*update_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value);
    ebpf_result_t (*update_entry_with_handle)(
        _In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, uintptr_t value_handle);
    ebpf_result_t (*update_entry_per_cpu)(
        _In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value);
    ebpf_result_t (*delete_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*next_key)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* previous_key, _Out_ uint8_t* next_key);
} ebpf_map_function_table_t;

const ebpf_map_definition_t*
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
    size_t map_struct_size, _In_ const ebpf_map_definition_t* map_definition, size_t extra_value_size)
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
    retval = ebpf_safe_size_t_add(map_struct_size, map_data_size, &full_map_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    // allocate
    map = ebpf_allocate(full_map_size);
    if (map == NULL) {
        goto Done;
    }
    memset(map, 0, full_map_size);

    map->ebpf_map_definition = *map_definition;
    map->data = ((uint8_t*)map) + map_struct_size;

Done:
    return map;
}

static ebpf_core_map_t*
_create_array_map(_In_ const ebpf_map_definition_t* map_definition)
{
    return _create_array_map_with_extra_value_size(sizeof(ebpf_core_map_t), map_definition, 0);
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
_update_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_opt_ const uint8_t* data)
{
    uint32_t key_value;

    if (!map || !key)
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
    return _create_array_map_with_extra_value_size(
        sizeof(ebpf_program_array_map_t), map_definition, sizeof(struct _ebpf_program*));
}

static void
_delete_array_map_with_references(_In_ ebpf_core_map_t* map)
{
    // The following addition is safe since it was checked during map creation.
    size_t actual_value_size = ((size_t)map->ebpf_map_definition.value_size) + sizeof(ebpf_object_t*);

    // Release all entry references.
    for (uint32_t i = 0; i < map->ebpf_map_definition.max_entries; i++) {
        uint8_t* entry = &map->data[i * actual_value_size];
        ebpf_object_t* object = *(ebpf_object_t**)(entry + map->ebpf_map_definition.value_size);
        ebpf_object_release_reference(object);
    }

    ebpf_free(map);
}

static ebpf_result_t
_associate_program_with_prog_array_map(_In_ ebpf_core_map_t* map, _In_ const ebpf_program_t* program)
{
    ebpf_assert(map->ebpf_map_definition.type == BPF_MAP_TYPE_PROG_ARRAY);
    ebpf_program_array_map_t* program_array = (ebpf_program_array_map_t*)map;

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

static ebpf_result_t
_update_prog_array_map_entry_with_handle(
    _In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_opt_ const uint8_t* value, uintptr_t value_handle)
{
    if (!map || !key || !value)
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
    size_t actual_value_size = ((size_t)map->ebpf_map_definition.value_size) + sizeof(struct _ebpf_program*);

    // Validate that the program type is
    // not in conflict with the map's program type.
    const ebpf_program_type_t* program_type = ebpf_program_type(program);
    ebpf_program_array_map_t* program_array = (ebpf_program_array_map_t*)map;
    ebpf_result_t result = EBPF_SUCCESS;

    ebpf_lock_state_t lock_state = ebpf_lock_lock(&map->lock);

    if (!program_array->is_program_type_set) {
        program_array->is_program_type_set = TRUE;
        program_array->program_type = *program_type;
    } else if (memcmp(&program_array->program_type, program_type, sizeof(*program_type)) != 0) {
        ebpf_object_release_reference((ebpf_object_t*)program);
        result = EBPF_INVALID_FD;
        goto Done;
    }

    // Store the literal value.
    uint8_t* entry = &map->data[*key * actual_value_size];
    if (value) {
        memcpy(entry, value, map->ebpf_map_definition.value_size);
    } else {
        memset(entry, 0, map->ebpf_map_definition.value_size);
    }

    // Store program pointer after the value.
    memcpy(entry + map->ebpf_map_definition.value_size, &program, sizeof(void*));

Done:
    ebpf_lock_unlock(&map->lock, lock_state);

    return result;
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
_update_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_opt_ const uint8_t* data)
{
    ebpf_result_t result;
    ebpf_lock_state_t lock_state;
    size_t entry_count = 0;
    uint8_t* value;
    if (!map || !key)
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

static ebpf_result_t
_ebpf_adjust_value_pointer(_In_ ebpf_map_t* map, _Inout_ uint8_t** value)
{
    uint32_t current_cpu;
    uint32_t max_cpu = map->ebpf_map_definition.value_size / PAD16(map->original_value_size);
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
    (*value) += PAD16((size_t)map->original_value_size) * current_cpu;
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
_update_entry_per_cpu(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value)
{
    uint8_t* target = ebpf_map_function_tables[map->ebpf_map_definition.type].find_entry(map, key);
    if (!target) {
        ebpf_result_t return_value =
            ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry(map, key, NULL);
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
     _create_prog_array_map,
     _delete_array_map_with_references,
     _associate_program_with_prog_array_map,
     _find_array_map_entry,
     _get_object_from_array_map_entry,
     NULL,
     _update_prog_array_map_entry_with_handle,
     NULL,
     _delete_prog_array_map_entry,
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
};

ebpf_result_t
ebpf_map_create(
    _In_ const ebpf_utf8_string_t* map_name,
    _In_ const ebpf_map_definition_t* ebpf_map_definition,
    _Outptr_ ebpf_map_t** ebpf_map)
{
    ebpf_map_t* local_map = NULL;
    ebpf_map_type_t type = ebpf_map_definition->type;
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t cpu_count;
    ebpf_get_cpu_count(&cpu_count);
    ebpf_map_definition_t local_map_definition = *ebpf_map_definition;
    switch (local_map_definition.type) {
    case BPF_MAP_TYPE_PERCPU_HASH:
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        local_map_definition.value_size = cpu_count * PAD16(local_map_definition.value_size);
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

    ebpf_object_initialize(
        &local_map->object,
        EBPF_OBJECT_MAP,
        (ebpf_free_object_t)ebpf_map_function_tables[local_map->ebpf_map_definition.type].delete_map);

    *ebpf_map = local_map;

Exit:
    if (result != EBPF_SUCCESS) {
        if (local_map) {
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
    uint8_t* return_value;
    if (!(flags & EBPF_MAP_FLAG_HELPER) && (key_size != map->ebpf_map_definition.key_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (!(flags & EBPF_MAP_FLAG_HELPER) && (value_size != map->ebpf_map_definition.value_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Disallow reads to prog array maps from this helper call for now.
    if ((flags & EBPF_MAP_FLAG_HELPER) && map->ebpf_map_definition.type == BPF_MAP_TYPE_PROG_ARRAY) {
        return EBPF_INVALID_ARGUMENT;
    }
    return_value = ebpf_map_function_tables[map->ebpf_map_definition.type].find_entry(map, key);
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
        return ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry_per_cpu(map, key, value);
    } else {
        return ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry(map, key, value);
    }
}

ebpf_result_t
ebpf_map_update_entry_with_handle(
    _In_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    uintptr_t value_handle)
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
        map, key, value, value_handle);
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
