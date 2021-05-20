/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#include "ebpf_platform.h"

struct _ebpf_hash_table
{
    struct _RTL_AVL_TABLE avl_table;
    ebpf_hash_table_compare_result_t (*compare_function)(const uint8_t* key1, const uint8_t* key2);
    size_t key_size;
    size_t value_size;
    void* (*allocate)(size_t size, ebpf_memory_type_t type);
    void (*free)(void* memory);
};

// NOTE:
// AVL tree gives a single struct containing both key and value.
// Compare can be called with a partial struct only containing the key.
// Do not access beyond map->ebpf_map_definition.key_size bytes.
static RTL_GENERIC_COMPARE_RESULTS
_ebpf_hash_map_compare(struct _RTL_AVL_TABLE* avl_table, void* first_struct, void* second_struct)
{
    ebpf_hash_table_t* table = (ebpf_hash_table_t*)avl_table;

    if (table->compare_function) {
        return (RTL_GENERIC_COMPARE_RESULTS)table->compare_function(
            (const uint8_t*)first_struct, (const uint8_t*)second_struct);
    } else {
        int result = memcmp(first_struct, second_struct, table->key_size);
        if (result < 0) {
            return GenericLessThan;
        } else if (result > 0) {
            return GenericGreaterThan;
        } else {
            return GenericEqual;
        }
    }
}

static void*
_ebpf_hash_table_allocate(struct _RTL_AVL_TABLE* avl_table, unsigned long byte_size)
{
    ebpf_hash_table_t* table = (ebpf_hash_table_t*)avl_table;
    return table->allocate(byte_size, EBPF_MEMORY_NO_EXECUTE);
}

static void
_ebpf_hash_table_free(struct _RTL_AVL_TABLE* avl_table, void* buffer)
{
    ebpf_hash_table_t* table = (ebpf_hash_table_t*)avl_table;
    table->free(buffer);
}

ebpf_result_t
ebpf_hash_table_create(
    ebpf_hash_table_t** hash_table,
    void* (*allocate)(size_t size, ebpf_memory_type_t type),
    void (*free)(void* memory),
    size_t key_size,
    size_t value_size,
    ebpf_hash_table_compare_result_t (*compare_function)(const uint8_t* key1, const uint8_t* key2))
{
    ebpf_result_t retval;
    ebpf_hash_table_t* table = NULL;

    // allocate
    table = ebpf_allocate(sizeof(ebpf_hash_table_t), EBPF_MEMORY_NO_EXECUTE);
    if (table == NULL) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    table->compare_function = compare_function;

    RtlInitializeGenericTableAvl(
        &table->avl_table, _ebpf_hash_map_compare, _ebpf_hash_table_allocate, _ebpf_hash_table_free, NULL);

    table->key_size = key_size;
    table->value_size = value_size;
    table->allocate = allocate;
    table->free = free;

    *hash_table = table;
    retval = EBPF_SUCCESS;
Done:
    return retval;
}

void
ebpf_hash_table_destroy(ebpf_hash_table_t* hash_table)
{
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;
    for (;;) {
        uint8_t* entry;
        entry = RtlEnumerateGenericTableAvl(table, TRUE);
        if (!entry)
            break;
        RtlDeleteElementGenericTableAvl(table, entry);
    }
    ebpf_free(hash_table);
}

ebpf_result_t
ebpf_hash_table_find(ebpf_hash_table_t* hash_table, const uint8_t* key, uint8_t** value)
{
    ebpf_result_t retval;
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;
    uint8_t* entry;

    entry = RtlLookupElementGenericTableAvl(table, (uint8_t*)key);

    if (entry) {
        *value = entry + hash_table->key_size;
        retval = EBPF_SUCCESS;
    } else {
        retval = EBPF_ERROR_NOT_FOUND;
    }
    return retval;
}

ebpf_result_t
ebpf_hash_table_update(ebpf_hash_table_t* hash_table, const uint8_t* key, const uint8_t* value)
{
    ebpf_result_t retval;
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;
    uint8_t* entry;
    uint8_t* temp = NULL;
    size_t temp_size = hash_table->key_size + hash_table->value_size;
    BOOLEAN new_entry;

    if (!hash_table || !key || !value) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    temp = ebpf_allocate(temp_size, EBPF_MEMORY_NO_EXECUTE);
    if (!temp) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    memcpy(temp, key, hash_table->key_size);
    memcpy(temp + hash_table->key_size, value, hash_table->value_size);

    entry = RtlInsertElementGenericTableAvl(table, temp, (uint32_t)temp_size, &new_entry);
    if (!entry) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    // Update existing entry
    memcpy(entry + hash_table->key_size, value, hash_table->value_size);
    retval = EBPF_SUCCESS;

Done:
    ebpf_free(temp);

    return retval;
}

ebpf_result_t
ebpf_hash_table_delete(ebpf_hash_table_t* hash_table, const uint8_t* key)
{
    BOOLEAN result;
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;

    result = RtlDeleteElementGenericTableAvl(table, (uint8_t*)key);
    return result ? EBPF_SUCCESS : EBPF_ERROR_NOT_FOUND;
}

ebpf_result_t
ebpf_hash_table_next_key(ebpf_hash_table_t* hash_table, const uint8_t* previous_key, uint8_t* next_key)
{
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;
    uint8_t* entry;
    void* restart_key;

    if (!previous_key) {
        entry = RtlEnumerateGenericTableAvl(table, TRUE);
    } else {
        // Note - We need a better option to resume the search when the element was
        // deleted.
        entry = RtlLookupFirstMatchingElementGenericTableAvl(table, (void*)previous_key, &restart_key);
        if (!entry) {
            // Entry deleted.

            // Start at the beginning of the table.
            entry = RtlEnumerateGenericTableAvl(table, TRUE);
            if (entry == NULL) {
                return EBPF_ERROR_NO_MORE_KEYS;
            }

            // Advance the cursor until we reach the first entry that is greater than
            // the key.
            while (!(_ebpf_hash_map_compare(table, (uint8_t*)previous_key, entry) == GenericGreaterThan)) {
                entry = RtlEnumerateGenericTableAvl(table, FALSE);
                if (!entry) {
                    break;
                }
            }
        } else {
            entry = RtlEnumerateGenericTableAvl(table, FALSE);
        }
    }
    if (entry == NULL) {
        return EBPF_ERROR_NO_MORE_KEYS;
    } else {
        memcpy(next_key, entry, hash_table->key_size);
    }
    return EBPF_SUCCESS;
}

size_t
ebpf_hash_table_key_count(ebpf_hash_table_t* hash_table)
{
    return hash_table->avl_table.NumberGenericTableElements;
}
