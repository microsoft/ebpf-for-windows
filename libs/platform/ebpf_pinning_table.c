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
    *pinning_table = ebpf_allocate(sizeof(ebpf_pinning_table_t));
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

    new_pinning_entry = ebpf_allocate(sizeof(ebpf_pinning_entry_t));
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

ebpf_result_t
ebpf_pinning_table_enumerate_entries(
    _In_ ebpf_pinning_table_t* pinning_table,
    ebpf_object_type_t object_type,
    _Out_ uint16_t* entry_count,
    _Outptr_result_buffer_maybenull_(*entry_count) ebpf_pinning_entry_t** pinning_entries)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state;
    uint16_t local_entry_count = 0;
    uint16_t entries_array_length = 0;
    ebpf_pinning_entry_t* local_pinning_entries = NULL;
    ebpf_utf8_string_t* next_object_name;
    ebpf_pinning_entry_t* new_entry = NULL;

    if ((entry_count == NULL) || (pinning_entries == NULL)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Get an estimate of how many entries are there in the pinning table without
    // acquiring lock.
    entries_array_length = (uint16_t)ebpf_hash_table_key_count(pinning_table->hash_table);

    // Exit if there are no entries.
    if (entries_array_length == 0)
        goto Exit;

    // Allocate an output array with the estimated size.
    local_pinning_entries = (ebpf_pinning_entry_t*)ebpf_allocate(
        sizeof(ebpf_pinning_entry_t) * entries_array_length, EBPF_MEMORY_NO_EXECUTE);
    if (local_pinning_entries == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Grab lock.
    ebpf_lock_lock(&pinning_table->lock, &state);

    // Loop through the entries in the hashtable.
    next_object_name = NULL;
    for (;;) {
        ebpf_pinning_entry_t** next_pinning_entry = NULL;

        // Find next pinning entry, if any.
        result = ebpf_hash_table_next_key_and_value(
            pinning_table->hash_table,
            (const uint8_t*)((next_object_name == NULL) ? NULL : &next_object_name),
            (uint8_t*)&next_object_name,
            (uint8_t**)&next_pinning_entry);

        if (result == EBPF_ERROR_NO_MORE_KEYS) {
            // Reached end of hashtable.
            result = EBPF_SUCCESS;
            break;
        }

        if (result != EBPF_SUCCESS)
            goto Exit_Locked;

        // Skip entries that don't match the input object type.
        if (object_type != ebpf_object_get_type((*next_pinning_entry)->object)) {
            continue;
        }

        local_entry_count++;

        if (local_entry_count > entries_array_length) {
            ebpf_pinning_entry_t* temp_array;
            uint16_t old_length = entries_array_length;
            uint16_t index;

            // Allocate a bigger output array with double the estimated size.
            entries_array_length <<= 1;
            if (entries_array_length < old_length) {
                // Overflow occured.
                result = EBPF_ERROR_ARITHMETIC_OVERFLOW;
                goto Exit_Locked;
            }
            temp_array = (ebpf_pinning_entry_t*)ebpf_allocate(
                sizeof(ebpf_pinning_entry_t) * entries_array_length, EBPF_MEMORY_NO_EXECUTE);
            if (temp_array == NULL) {
                result = EBPF_NO_MEMORY;
                goto Exit_Locked;
            }

            // Copy over the old array.
            for (index = 0; index < (local_entry_count - 1); index++) {
                ebpf_pinning_entry_t* source = &local_pinning_entries[index];
                ebpf_pinning_entry_t* destination = &temp_array[index];

                *destination = *source;
            }

            // Free old array.
            ebpf_free(&local_pinning_entries);

            // Set array to new buffer.
            local_pinning_entries = temp_array;
        }

        // Copy the next pinning entry to a new entry in the output array.
        new_entry = &local_pinning_entries[local_entry_count - 1];
        new_entry->object = (*next_pinning_entry)->object;

        // Take reference on underlying ebpf_object.
        ebpf_object_acquire_reference(new_entry->object);

        // Duplicate pinning object name.
        result = ebpf_duplicate_utf8_string(&new_entry->name, &(*next_pinning_entry)->name);
        if (result != EBPF_SUCCESS)
            goto Exit_Locked;
    }

Exit_Locked:
    // Release lock.
    ebpf_lock_unlock(&pinning_table->lock, &state);
Exit:
    if (result != EBPF_SUCCESS) {
        ebpf_pinning_entries_release(local_entry_count, local_pinning_entries);
        local_entry_count = 0;
        local_pinning_entries = NULL;
    }

    // Set output parameters.
    *entry_count = local_entry_count;
    *pinning_entries = local_pinning_entries;

    return result;
}

void
ebpf_pinning_entries_release(uint16_t entry_count, _In_count_(entry_count) ebpf_pinning_entry_t* pinning_entries)
{
    uint16_t index;

    for (index = 0; index < entry_count; index++) {
        ebpf_pinning_entry_t* entry = &pinning_entries[index];
        ebpf_free(entry->name.value);
        ebpf_object_release_reference(entry->object);
    }
    ebpf_free(pinning_entries);
}
