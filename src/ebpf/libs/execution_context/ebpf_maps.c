/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include "pch.h"
#include "ebpf_protocol.h"

#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_platform.h"

static ebpf_core_map_t* ebpf_create_array_map(
    _In_ const ebpf_map_definition_t* map_definition)
{
    ebpf_error_code_t retval;
    size_t map_entry_size = sizeof(ebpf_core_map_t);
    size_t map_data_size = 0;
    ebpf_core_map_t* map = NULL;

    retval = ebpf_safe_size_t_multiply(map_definition->max_entries, map_definition->value_size, &map_data_size);
    if (retval != EBPF_ERROR_SUCCESS)
    {
        goto Done;
    }

    retval = ebpf_safe_size_t_multiply(map_data_size, map_entry_size, &map_entry_size);
    if (retval != EBPF_ERROR_SUCCESS)
    {
        goto Done;
    }

    // allocate
    map = ebpf_allocate(map_entry_size, EBPF_MEMORY_NO_EXECUTE);
    if (map == NULL) {
        goto Done;
    }
    memset(map, 0, map_entry_size);

    map->ebpf_map_definition = *map_definition;
    map->data = (uint8_t*)(map + 1);

Done:
    return map;
}

static void ebpf_delete_array_map(
    _In_ ebpf_core_map_t* map)
{
    ebpf_free(map);
}

static uint8_t* ebpf_lookup_array_map_entry(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key)
{
    uint32_t key_value;
    if (!map || !key)
        return NULL;

    key_value = *(uint32_t*)key;

    if (key_value > map->ebpf_map_definition.max_entries)
        return NULL;

    return &map->data[key_value * map->ebpf_map_definition.value_size];
}

static ebpf_error_code_t ebpf_update_array_map(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key, 
    _In_ const uint8_t* data)
{
    uint32_t key_value;
    if (!map || !key)
        return EBPF_ERROR_INVALID_PARAMETER;

    key_value = *(uint32_t*)key;

    if (key_value > map->ebpf_map_definition.max_entries)
        return EBPF_ERROR_INVALID_PARAMETER;

    uint8_t* entry = &map->data[*key * map->ebpf_map_definition.value_size];
    memcpy(entry, data, map->ebpf_map_definition.value_size);
    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t ebpf_delete_array_entry(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key)
{
    uint32_t key_value;
    if (!map || !key)
        return EBPF_ERROR_INVALID_PARAMETER;

    key_value = *(uint32_t*)key;

    if (key_value > map->ebpf_map_definition.max_entries)
        return EBPF_ERROR_INVALID_PARAMETER;

    uint8_t* entry = &map->data[key_value * map->ebpf_map_definition.value_size];
    memset(entry, 0, map->ebpf_map_definition.value_size);
    return EBPF_ERROR_SUCCESS;
}

static
ebpf_core_map_t* ebpf_create_hash_map(
    _In_ const ebpf_map_definition_t* map_definition)
{
    ebpf_error_code_t retval;
    size_t map_size = sizeof(ebpf_core_map_t);
    ebpf_core_map_t* map = NULL;

    map = ebpf_allocate(map_size, EBPF_MEMORY_NO_EXECUTE);
    if (map == NULL)
    {
        retval = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }

    map->ebpf_map_definition = *map_definition;
    map->data = NULL;

    retval = ebpf_hash_table_create((ebpf_hash_table_t**)&map->data, map->ebpf_map_definition.key_size, map->ebpf_map_definition.value_size);
    if (retval != EBPF_ERROR_SUCCESS)
    {
        goto Done;
    }
    retval = EBPF_ERROR_SUCCESS;

Done:
    if (retval != EBPF_ERROR_SUCCESS)
    {
        if (map && map->data)
        {
            ebpf_hash_table_destroy((ebpf_hash_table_t *)map->data);
        }
        ebpf_free(map);
        map = NULL;
    }
    return map;
}

static void ebpf_delete_hash_map(
    _In_ ebpf_core_map_t* map)
{
    ebpf_hash_table_destroy((ebpf_hash_table_t*)map->data);
    ebpf_free(map);
}

static uint8_t* ebpf_lookup_hash_map_entry(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key)
{
    ebpf_lock_state_t lock_state;
    uint8_t* value = NULL;
    if (!map || !key)
        return NULL;

    ebpf_lock_lock(&map->lock, &lock_state);
    if (ebpf_hash_table_lookup((ebpf_hash_table_t*)map->data, key, &value) != EBPF_ERROR_SUCCESS)
    {
        value = NULL;
    }
    ebpf_lock_unlock(&map->lock, &lock_state);

    return value;
}

static ebpf_error_code_t ebpf_update_hash_map(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key, 
    _In_ const uint8_t* data)
{
    ebpf_error_code_t result;
    ebpf_lock_state_t lock_state;
    if (!map || !key || !data)
        return EBPF_ERROR_INVALID_PARAMETER;

    ebpf_lock_lock(&map->lock, &lock_state);
    result = ebpf_hash_table_update((ebpf_hash_table_t*)map->data, key, data);
    ebpf_lock_unlock(&map->lock, &lock_state);
    return EBPF_ERROR_SUCCESS;
}

static ebpf_error_code_t ebpf_delete_hash_entry(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key)
{
    ebpf_error_code_t result;
    ebpf_lock_state_t lock_state;
    if (!map || !key)
        return EBPF_ERROR_INVALID_PARAMETER;

    ebpf_lock_lock(&map->lock, &lock_state);
    result = ebpf_hash_table_delete((ebpf_hash_table_t*)map->data, key);
    ebpf_lock_unlock(&map->lock, &lock_state);
    return EBPF_ERROR_SUCCESS;

}

ebpf_map_function_table_t ebpf_map_function_tables[] =
{
    { // EBPF_MAP_TYPE_UNSPECIFIED
        NULL
    },
    { // EBPF_MAP_TYPE_HASH
        ebpf_create_hash_map,
        ebpf_delete_hash_map,
        ebpf_lookup_hash_map_entry,
        ebpf_update_hash_map,
        ebpf_delete_hash_entry
    },
    { // EBPF_MAP_TYPE_ARRAY
        ebpf_create_array_map,
        ebpf_delete_array_map,
        ebpf_lookup_array_map_entry,
        ebpf_update_array_map,
        ebpf_delete_array_entry
    },
};