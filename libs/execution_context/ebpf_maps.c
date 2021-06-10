/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_maps.h"
#include "ebpf_epoch.h"
#include "ebpf_object.h"

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
    ebpf_result_t (*update_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value);
    ebpf_result_t (*delete_entry)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*next_key)(_In_ ebpf_core_map_t* map, _In_ const uint8_t* previous_key, _Out_ uint8_t* next_key);
} ebpf_map_function_table_t;

extern ebpf_map_function_table_t ebpf_map_function_tables[EBPF_MAP_TYPE_ARRAY + 1];

ebpf_result_t
ebpf_map_create(const ebpf_map_definition_t* ebpf_map_definition, ebpf_map_t** ebpf_map)
{
    ebpf_map_t* local_map = NULL;
    size_t type = ebpf_map_definition->type;

    if (ebpf_map_definition->type > EBPF_MAP_TYPE_ARRAY)
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

ebpf_map_definition_t*
ebpf_map_get_definition(ebpf_map_t* map)
{
    return &map->ebpf_map_definition;
}

uint8_t*
ebpf_map_find_entry(ebpf_map_t* map, const uint8_t* key)
{
    return ebpf_map_function_tables[map->ebpf_map_definition.type].find_entry(map, key);
}

ebpf_result_t
ebpf_map_update_entry(ebpf_map_t* map, const uint8_t* key, const uint8_t* value)
{
    return ebpf_map_function_tables[map->ebpf_map_definition.type].update_entry(map, key, value);
}

ebpf_result_t
ebpf_map_delete_entry(ebpf_map_t* map, const uint8_t* key)
{
    return ebpf_map_function_tables[map->ebpf_map_definition.type].delete_entry(map, key);
}

ebpf_result_t
ebpf_map_next_key(ebpf_map_t* map, const uint8_t* previous_key, uint8_t* next_key)
{
    return ebpf_map_function_tables[map->ebpf_map_definition.type].next_key(map, previous_key, next_key);
}

static ebpf_core_map_t*
ebpf_create_array_map(_In_ const ebpf_map_definition_t* map_definition)
{
    ebpf_result_t retval;
    size_t map_entry_size = sizeof(ebpf_core_map_t);
    size_t map_data_size = 0;
    ebpf_core_map_t* map = NULL;

    retval = ebpf_safe_size_t_multiply(map_definition->max_entries, map_definition->value_size, &map_data_size);
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

static void
ebpf_delete_array_map(_In_ ebpf_core_map_t* map)
{
    ebpf_free(map);
}

static uint8_t*
ebpf_find_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    uint32_t key_value;
    if (!map || !key)
        return NULL;

    key_value = *(uint32_t*)key;

    if (key_value > map->ebpf_map_definition.max_entries)
        return NULL;

    return &map->data[key_value * map->ebpf_map_definition.value_size];
}

static ebpf_result_t
ebpf_update_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* data)
{
    uint32_t key_value;
    if (!map || !key)
        return EBPF_INVALID_ARGUMENT;

    key_value = *(uint32_t*)key;

    if (key_value > map->ebpf_map_definition.max_entries)
        return EBPF_INVALID_ARGUMENT;

    uint8_t* entry = &map->data[*key * map->ebpf_map_definition.value_size];
    memcpy(entry, data, map->ebpf_map_definition.value_size);
    return EBPF_SUCCESS;
}

static ebpf_result_t
ebpf_delete_array_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    uint32_t key_value;
    if (!map || !key)
        return EBPF_INVALID_ARGUMENT;

    key_value = *(uint32_t*)key;

    if (key_value > map->ebpf_map_definition.max_entries)
        return EBPF_KEY_NOT_FOUND;

    uint8_t* entry = &map->data[key_value * map->ebpf_map_definition.value_size];
    memset(entry, 0, map->ebpf_map_definition.value_size);
    return EBPF_SUCCESS;
}

static ebpf_result_t
ebpf_next_array_map_key(_In_ ebpf_core_map_t* map, _In_ const uint8_t* previous_key, _Out_ uint8_t* next_key)
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
ebpf_create_hash_map(_In_ const ebpf_map_definition_t* map_definition)
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
ebpf_delete_hash_map(_In_ ebpf_core_map_t* map)
{
    ebpf_lock_destroy(&map->lock);
    ebpf_hash_table_destroy((ebpf_hash_table_t*)map->data);
    ebpf_free(map);
}

static uint8_t*
ebpf_find_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    ebpf_lock_state_t lock_state;
    uint8_t* value = NULL;
    if (!map || !key)
        return NULL;

    ebpf_lock_lock(&map->lock, &lock_state);
    if (ebpf_hash_table_find((ebpf_hash_table_t*)map->data, key, &value) != EBPF_SUCCESS) {
        value = NULL;
    }
    ebpf_lock_unlock(&map->lock, &lock_state);

    return value;
}

static ebpf_result_t
ebpf_update_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* data)
{
    ebpf_result_t result;
    ebpf_lock_state_t lock_state;
    size_t entry_count = 0;
    uint8_t* value;
    if (!map || !key || !data)
        return EBPF_INVALID_ARGUMENT;

    ebpf_lock_lock(&map->lock, &lock_state);
    entry_count = ebpf_hash_table_key_count((ebpf_hash_table_t*)map->data);

    if ((entry_count == map->ebpf_map_definition.max_entries) &&
        (ebpf_hash_table_find((ebpf_hash_table_t*)map->data, key, &value) != EBPF_SUCCESS))
        result = EBPF_INVALID_ARGUMENT;
    else
        result = ebpf_hash_table_update((ebpf_hash_table_t*)map->data, key, data);
    ebpf_lock_unlock(&map->lock, &lock_state);
    return result;
}

static ebpf_result_t
ebpf_delete_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    ebpf_result_t result;
    ebpf_lock_state_t lock_state;
    if (!map || !key)
        return EBPF_INVALID_ARGUMENT;

    ebpf_lock_lock(&map->lock, &lock_state);
    result = ebpf_hash_table_delete((ebpf_hash_table_t*)map->data, key);
    ebpf_lock_unlock(&map->lock, &lock_state);
    return result;
}

static ebpf_result_t
ebpf_next_hash_map_key(_In_ ebpf_core_map_t* map, _In_ const uint8_t* previous_key, _Out_ uint8_t* next_key)
{
    ebpf_result_t result;
    ebpf_lock_state_t lock_state;
    if (!map || !next_key)
        return EBPF_INVALID_ARGUMENT;

    ebpf_lock_lock(&map->lock, &lock_state);
    result = ebpf_hash_table_next_key((ebpf_hash_table_t*)map->data, previous_key, next_key);
    ebpf_lock_unlock(&map->lock, &lock_state);
    return result;
}

ebpf_map_function_table_t ebpf_map_function_tables[] = {
    {// EBPF_MAP_TYPE_UNSPECIFIED
     NULL},
    {// EBPF_MAP_TYPE_HASH
     ebpf_create_hash_map,
     ebpf_delete_hash_map,
     ebpf_find_hash_map_entry,
     ebpf_update_hash_map_entry,
     ebpf_delete_hash_map_entry,
     ebpf_next_hash_map_key},
    {// EBPF_MAP_TYPE_ARRAY
     ebpf_create_array_map,
     ebpf_delete_array_map,
     ebpf_find_array_map_entry,
     ebpf_update_array_map_entry,
     ebpf_delete_array_map_entry,
     ebpf_next_array_map_key},
};
