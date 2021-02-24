/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include <ntdef.h>
#include <ntddk.h>
#include <netiodef.h>
#include <ntintsafe.h>

#include "types.h"
#include "protocol.h"

#include "ebpf_core.h"
#include "types.h"

#include "ebpf_maps.h"


static ebpf_core_map_entry_t* ebpf_create_array_map(
    _In_ const ebpf_map_definition_t* map_definition)
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T map_entry_size = sizeof(ebpf_core_map_entry_t);
    SIZE_T map_data_size = 0;
    ebpf_core_map_entry_t* map = NULL;

    status = RtlSizeTMult(map_definition->max_entries, map_definition->value_size, &map_data_size);
    if (status != STATUS_SUCCESS)
    {
        goto Done;
    }

    status = RtlSizeTMult(map_data_size, map_entry_size, &map_entry_size);
    if (status != STATUS_SUCCESS)
    {
        goto Done;
    }

    // allocate
    map = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        map_entry_size,
        ebpfPoolTag
    );
    if (map == NULL) {
        goto Done;
    }
    memset(map, 0, map_entry_size);

    map->map.ebpf_map_definition = *map_definition;
    map->map.data = (uint8_t*)(map + 1);
    KeInitializeSpinLock(&map->map.lock);

Done:
    return map;
}

static void ebpf_delete_array_map(
    _In_ ebpf_core_map_entry_t* map)
{
    ExFreePool(map);
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

static NTSTATUS ebpf_update_array_map(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key, 
    _In_ const uint8_t* data)
{
    uint32_t key_value;
    if (!map || !key)
        return STATUS_INVALID_PARAMETER;

    key_value = *(uint32_t*)key;

    if (key_value > map->ebpf_map_definition.max_entries)
        return STATUS_INVALID_PARAMETER;

    uint8_t* entry = &map->data[*key * map->ebpf_map_definition.value_size];
    memcpy(entry, data, map->ebpf_map_definition.value_size);
    return STATUS_SUCCESS;
}

static NTSTATUS ebpf_delete_array_entry(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key)
{
    uint32_t key_value;
    if (!map || !key)
        return STATUS_INVALID_PARAMETER;

    key_value = *(uint32_t*)key;

    if (key_value > map->ebpf_map_definition.max_entries)
        return STATUS_INVALID_PARAMETER;

    uint8_t* entry = &map->data[key_value * map->ebpf_map_definition.value_size];
    memset(entry, 0, map->ebpf_map_definition.value_size);
    return STATUS_SUCCESS;
}

// NOTE:
// AVL tree gives a single struct containing both key and value
// Compare can be called with a partial struct only containing the key.
// Do not access beyond map->ebpf_map_definition.key_size bytes.
static RTL_GENERIC_COMPARE_RESULTS
ebpf_hash_map_compare(
    _In_ struct _RTL_AVL_TABLE* table,
    _In_ PVOID  first_struct,
    _In_ PVOID  second_struct
)
{
    ebpf_core_map_t* map = table->TableContext;
    int result = memcmp(first_struct, second_struct, map->ebpf_map_definition.key_size);
    if (result < 0)
    {
        return GenericLessThan;
    }
    else if (result > 0)
    {
        return GenericGreaterThan;
    }
    else
    {
        return GenericEqual;
    }
}

static PVOID
ebpf_hash_map_allocate(
    _In_ struct _RTL_AVL_TABLE* table,
    _In_ CLONG  byte_size
)
{
    UNREFERENCED_PARAMETER(table);
    return ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        byte_size,
        ebpfPoolTag
    );
}

static VOID
ebpf_hash_map_free(
    _In_ struct _RTL_AVL_TABLE* table,
    _In_ PVOID  buffer
)
{
    UNREFERENCED_PARAMETER(table);
    ExFreePool(buffer);
}

static
ebpf_core_map_entry_t* ebpf_create_hash_map(
    _In_ const ebpf_map_definition_t* map_definition)
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T map_entry_size = sizeof(ebpf_core_map_entry_t);
    SIZE_T map_data_size = sizeof(RTL_AVL_TABLE);
    ebpf_core_map_entry_t* map = NULL;
    PRTL_AVL_TABLE table = NULL;

    status = RtlSizeTMult(map_definition->max_entries, map_definition->value_size, &map_data_size);
    if (status != STATUS_SUCCESS)
    {
        goto Done;
    }

    status = RtlSizeTMult(map_data_size, map_entry_size, &map_entry_size);
    if (status != STATUS_SUCCESS)
    {
        goto Done;
    }

    // allocate
    map = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        map_entry_size,
        ebpfPoolTag
    );
    if (map == NULL) {
        goto Done;
    }
    memset(map, 0, map_entry_size);

    map->map.ebpf_map_definition = *map_definition;
    map->map.data = (uint8_t*)(map + 1);
    KeInitializeSpinLock(&map->map.lock);

    table = (PRTL_AVL_TABLE)map->map.data;
    RtlInitializeGenericTableAvl(table, ebpf_hash_map_compare, ebpf_hash_map_allocate, ebpf_hash_map_free, &map->map);

Done:
    return map;
}

static void ebpf_delete_hash_map(
    _In_ ebpf_core_map_entry_t* map)
{
    UNREFERENCED_PARAMETER(map);
}

static uint8_t* ebpf_lookup_hash_map_entry(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key)
{
    PRTL_AVL_TABLE table = NULL;
    KIRQL old_irql;
    uint8_t* entry;
    if (!map || !key)
        return NULL;

    table = (PRTL_AVL_TABLE)map->data;
    KeAcquireSpinLock(&map->lock, &old_irql);
    entry = RtlLookupElementGenericTableAvl(table, (uint8_t*)key);
    KeReleaseSpinLock(&map->lock, old_irql);
    if (!entry)
        return NULL;

    return entry + map->ebpf_map_definition.key_size;
}

static NTSTATUS ebpf_update_hash_map(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key, 
    _In_ const uint8_t* data)
{
    PRTL_AVL_TABLE table = NULL;
    uint8_t* temp = NULL;
    size_t temp_size = (size_t)map->ebpf_map_definition.key_size + (size_t)map->ebpf_map_definition.value_size;
    uint8_t* entry = NULL;
    BOOLEAN new_entry;
    NTSTATUS status;
    KIRQL old_irql;

    if (!map || !key || !data)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    table = (PRTL_AVL_TABLE)map->data;

    temp = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        temp_size,
        ebpfPoolTag
    );

    if (temp == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    memcpy(temp, key, map->ebpf_map_definition.key_size);
    memcpy(temp + map->ebpf_map_definition.key_size, data, map->ebpf_map_definition.value_size);

    KeAcquireSpinLock(&map->lock, &old_irql);
    entry = RtlInsertElementGenericTableAvl(table, temp, (CLONG)temp_size, &new_entry);
    KeReleaseSpinLock(&map->lock, old_irql);
    if (entry == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    // Update existing entry
    if (!new_entry)
    {
        memcpy(entry + map->ebpf_map_definition.key_size, data, map->ebpf_map_definition.value_size);
    }

Done:
    if (temp != NULL)
    {
        ExFreePool(temp);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ebpf_delete_hash_entry(
    _In_ ebpf_core_map_t* map, 
    _In_ const uint8_t* key)
{
    PRTL_AVL_TABLE table = NULL;
    BOOLEAN result;
    KIRQL old_irql;

    if (!map || !key)
        return STATUS_INVALID_PARAMETER;

    table = (PRTL_AVL_TABLE)map->data;

    KeAcquireSpinLock(&map->lock, &old_irql);
    result = RtlDeleteElementGenericTableAvl(table, (uint8_t*)key);
    KeReleaseSpinLock(&map->lock, old_irql);

    return result == FALSE ? STATUS_NOT_FOUND : STATUS_SUCCESS;
}

ebpf_map_function_table_t ebpf_map_function_tables[3] =
{
    { // EBPF_MAP_TYPE_UNSPECIFIED
        NULL
    },
    { // EBPF_MAP_TYPE_ARRAY
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