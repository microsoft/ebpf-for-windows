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
    void* (*allocate)(size_t size);
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
    return table->allocate(byte_size);
}

static void
_ebpf_hash_table_free(struct _RTL_AVL_TABLE* avl_table, void* buffer)
{
    ebpf_hash_table_t* table = (ebpf_hash_table_t*)avl_table;
    table->free(buffer);
}

ebpf_result_t
ebpf_hash_table_create(
    _Out_ ebpf_hash_table_t** hash_table,
    _In_ void* (*allocate)(size_t size),
    _In_ void (*free)(void* memory),
    size_t key_size,
    size_t value_size,
    _In_opt_ ebpf_hash_table_compare_result_t (*compare_function)(const uint8_t* key1, const uint8_t* key2))
{
    ebpf_result_t retval;
    ebpf_hash_table_t* table = NULL;

    // allocate
    table = ebpf_allocate(sizeof(ebpf_hash_table_t));
    if (table == NULL) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    table->compare_function = compare_function;

#pragma warning(push)
#pragma warning(disable : 28023) // Function not marked with _Function_class_ annotation
    RtlInitializeGenericTableAvl(
        &table->avl_table, _ebpf_hash_map_compare, _ebpf_hash_table_allocate, _ebpf_hash_table_free, NULL);
#pragma warning(pop)

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
ebpf_hash_table_destroy(_In_ _Pre_maybenull_ _Post_invalid_ ebpf_hash_table_t* hash_table)
{
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;
    if (!hash_table) {
        return;
    }

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
ebpf_hash_table_find(
    _In_ ebpf_hash_table_t* hash_table,
    _In_ _Readable_bytes_(hash_table->key_size) const uint8_t* key,
    _Outptr_ _Writable_bytes_(hash_table->value_size) uint8_t** value)
{
    ebpf_result_t retval;
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;
    uint8_t* entry;

    entry = RtlLookupElementGenericTableAvl(table, (uint8_t*)key);

    if (entry) {
        *value = entry + hash_table->key_size;
        retval = EBPF_SUCCESS;
    } else {
        retval = EBPF_KEY_NOT_FOUND;
    }
    return retval;
}

ebpf_result_t
ebpf_hash_table_update(
    _In_ ebpf_hash_table_t* hash_table,
    _In_ _Readable_bytes_(hash_table->key_size) const uint8_t* key,
    _In_ _Readable_bytes_(hash_table->value_size) const uint8_t* value)
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

    temp = ebpf_allocate(temp_size);
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
ebpf_hash_table_delete(
    _In_ ebpf_hash_table_t* hash_table, _In_ _Readable_bytes_(hash_table->key_size) const uint8_t* key)
{
    BOOLEAN result;
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;

    result = RtlDeleteElementGenericTableAvl(table, (uint8_t*)key);
    return result ? EBPF_SUCCESS : EBPF_KEY_NOT_FOUND;
}

ebpf_result_t
ebpf_hash_table_next_key_and_value(
    _In_ ebpf_hash_table_t* hash_table,
    _In_opt_ const uint8_t* previous_key,
    _Out_ _Writable_bytes_(hash_table->key_size) uint8_t* next_key,
    _Outptr_opt_ _Writable_bytes_(hash_table->value_size) uint8_t** value)
{
    ebpf_result_t result = EBPF_SUCCESS;
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;
    uint8_t* entry;
    void* restart_key;

    if (value != NULL)
        *value = NULL;

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
                return EBPF_NO_MORE_KEYS;
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
        result = EBPF_NO_MORE_KEYS;
        goto Exit;
    } else {
        memcpy(next_key, entry, hash_table->key_size);
        if (value != NULL)
            *value = entry + hash_table->key_size;
    }

Exit:
    return result;
}

ebpf_result_t
ebpf_hash_table_next_key(
    _In_ ebpf_hash_table_t* hash_table,
    _In_opt_ _Readable_bytes_(hash_table->key_size) const uint8_t* previous_key,
    _Out_ _Writable_bytes_(hash_table->value_size) uint8_t* next_key)
{
    return ebpf_hash_table_next_key_and_value(hash_table, previous_key, next_key, NULL);
}

size_t
ebpf_hash_table_key_count(_In_ ebpf_hash_table_t* hash_table)
{
    return hash_table->avl_table.NumberGenericTableElements;
}
