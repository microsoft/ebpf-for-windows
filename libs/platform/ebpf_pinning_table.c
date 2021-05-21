/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#include "ebpf_pinning_table.h"

#include "ebpf_object.h"

typedef struct _ebpf_pinning_table
{
    ebpf_hash_table_t* hash_table;
    ebpf_lock_t lock;
} ebpf_pinning_table_t;

typedef struct _ebpf_pinning_entry
{
    ebpf_utf8_string_t name;
    ebpf_object_t* object;
} ebpf_pinning_entry_t;

static ebpf_hash_table_compare_result_t
_ebpf_pining_table_compare_function(const uint8_t* key1, const uint8_t* key2)
{
    const ebpf_utf8_string_t* first_key = *(ebpf_utf8_string_t**)key1;
    const ebpf_utf8_string_t* second_key = *(ebpf_utf8_string_t**)key2;
    size_t min_length = min(first_key->length, second_key->length);

    // Note: This is not a lexicographical sort order.
    int compare_result = memcmp(first_key->value, second_key->value, min_length);
    if (compare_result < 0)
        return EBPF_HASH_TABLE_LESS_THAN;
    else if (compare_result > 0)
        return EBPF_HASH_TABLE_GREATER_THAN;
    else if (first_key->length < second_key->length)
        return EBPF_HASH_TABLE_LESS_THAN;
    else if (first_key->length > second_key->length)
        return EBPF_HASH_TABLE_GREATER_THAN;
    else
        return EBPF_HASH_TABLE_EQUAL;
}

static void
_ebpf_pinning_entry_free(ebpf_pinning_entry_t* pinning_entry)
{
    if (!pinning_entry) {
        return;
    }
    ebpf_object_release_reference(pinning_entry->object);
    ebpf_free(pinning_entry->name.value);
    ebpf_free(pinning_entry);
}

ebpf_result_t
ebpf_pinning_table_allocate(ebpf_pinning_table_t** pinning_table)
{
    ebpf_result_t return_value;
    *pinning_table = ebpf_allocate(sizeof(ebpf_pinning_table_t), EBPF_MEMORY_NO_EXECUTE);
    if (*pinning_table == NULL) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(*pinning_table, 0, sizeof(ebpf_pinning_table_t));

    ebpf_lock_create(&(*pinning_table)->lock);

    return_value = ebpf_hash_table_create(
        &(*pinning_table)->hash_table,
        ebpf_allocate,
        ebpf_free,
        sizeof(ebpf_utf8_string_t*),
        sizeof(ebpf_pinning_entry_t*),
        _ebpf_pining_table_compare_function);

    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = EBPF_SUCCESS;
Done:
    if (return_value != EBPF_SUCCESS) {
        if ((*pinning_table))
            ebpf_hash_table_destroy((*pinning_table)->hash_table);

        ebpf_free(*pinning_table);
    }

    return return_value;
}

void
ebpf_pinning_table_free(ebpf_pinning_table_t* pinning_table)
{
    ebpf_result_t return_value;
    ebpf_utf8_string_t* key;

    for (;;) {
        return_value = ebpf_hash_table_next_key(pinning_table->hash_table, NULL, (uint8_t*)&key);
        if (return_value != EBPF_SUCCESS) {
            break;
        }
        ebpf_pinning_table_delete(pinning_table, key);
    }

    ebpf_hash_table_destroy(pinning_table->hash_table);
    ebpf_free(pinning_table);
}

ebpf_result_t
ebpf_pinning_table_insert(ebpf_pinning_table_t* pinning_table, const ebpf_utf8_string_t* name, ebpf_object_t* object)
{
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    ebpf_utf8_string_t* new_key;
    ebpf_pinning_entry_t* new_pinning_entry;
    const ebpf_utf8_string_t* existing_key = name;
    ebpf_pinning_entry_t** existing_pinning_entry;

    new_pinning_entry = ebpf_allocate(sizeof(ebpf_pinning_entry_t), EBPF_MEMORY_NO_EXECUTE);
    if (!new_pinning_entry) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    return_value = ebpf_duplicate_utf8_string(&new_pinning_entry->name, name);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    new_pinning_entry->object = object;
    ebpf_object_acquire_reference(object);
    new_key = &new_pinning_entry->name;

    ebpf_lock_lock(&pinning_table->lock, &state);

    return_value = ebpf_hash_table_find(
        pinning_table->hash_table, (const uint8_t*)&existing_key, (uint8_t**)&existing_pinning_entry);
    if (return_value == EBPF_SUCCESS) {
        return_value = EBPF_OBJECT_ALREADY_EXISTS;
    } else {
        return_value = ebpf_hash_table_update(
            pinning_table->hash_table, (const uint8_t*)&new_key, (const uint8_t*)&new_pinning_entry);
        if (return_value == EBPF_SUCCESS)
            new_pinning_entry = NULL;
    }

    ebpf_lock_unlock(&pinning_table->lock, &state);

Done:
    _ebpf_pinning_entry_free(new_pinning_entry);

    return return_value;
}

ebpf_result_t
ebpf_pinning_table_find(ebpf_pinning_table_t* pinning_table, const ebpf_utf8_string_t* name, ebpf_object_t** object)
{
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    const ebpf_utf8_string_t* existing_key = name;
    ebpf_pinning_entry_t** existing_pinning_entry;

    ebpf_lock_lock(&pinning_table->lock, &state);
    return_value = ebpf_hash_table_find(
        pinning_table->hash_table, (const uint8_t*)&existing_key, (uint8_t**)&existing_pinning_entry);

    if (return_value == EBPF_SUCCESS) {
        *object = (*existing_pinning_entry)->object;
        ebpf_object_acquire_reference(*object);
    }

    ebpf_lock_unlock(&pinning_table->lock, &state);

    return return_value;
}

ebpf_result_t
ebpf_pinning_table_delete(ebpf_pinning_table_t* pinning_table, const ebpf_utf8_string_t* name)
{
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    const ebpf_utf8_string_t* existing_key = name;
    ebpf_pinning_entry_t** existing_pinning_entry;

    ebpf_lock_lock(&pinning_table->lock, &state);
    return_value = ebpf_hash_table_find(
        pinning_table->hash_table, (const uint8_t*)&existing_key, (uint8_t**)&existing_pinning_entry);
    if (return_value == EBPF_SUCCESS) {
        ebpf_pinning_entry_t* entry = *existing_pinning_entry;
        // Note: Can't fail because we first checked the entry exists.
        ebpf_hash_table_delete(pinning_table->hash_table, (const uint8_t*)&existing_key);
        _ebpf_pinning_entry_free(entry);
    }
    ebpf_lock_unlock(&pinning_table->lock, &state);

    return return_value;
}
