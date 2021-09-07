// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_pinning_table.h"

#include "ebpf_object.h"

#define EBPF_PINNING_TABLE_BUCKET_COUNT 64

typedef struct _ebpf_pinning_table
{
    _Requires_lock_held_(&lock) ebpf_hash_table_t* hash_table;
    ebpf_lock_t lock;
} ebpf_pinning_table_t;

static void
_ebpf_pinning_table_extract(_In_ const uint8_t* value, _Outptr_ const uint8_t** data, _Out_ size_t* length)
{
    const ebpf_utf8_string_t* key = *(ebpf_utf8_string_t**)value;
    *data = key->value;
    *length = key->length;
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
        EBPF_PINNING_TABLE_BUCKET_COUNT,
        _ebpf_pinning_table_extract);

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
    ebpf_utf8_string_t* key = NULL;

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

    state = ebpf_lock_lock(&pinning_table->lock);

    return_value = ebpf_hash_table_update(
        pinning_table->hash_table,
        (const uint8_t*)&new_key,
        (const uint8_t*)&new_pinning_entry,
        EBPF_HASH_TABLE_OPERATION_INSERT);
    if (return_value == EBPF_KEY_ALREADY_EXISTS) {
        return_value = EBPF_OBJECT_ALREADY_EXISTS;
    } else if (return_value == EBPF_SUCCESS)
        new_pinning_entry = NULL;

    ebpf_lock_unlock(&pinning_table->lock, state);

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

    state = ebpf_lock_lock(&pinning_table->lock);
    return_value = ebpf_hash_table_find(
        pinning_table->hash_table, (const uint8_t*)&existing_key, (uint8_t**)&existing_pinning_entry);

    if (return_value == EBPF_SUCCESS) {
        *object = (*existing_pinning_entry)->object;
        ebpf_object_acquire_reference(*object);
    }

    ebpf_lock_unlock(&pinning_table->lock, state);

    return return_value;
}

ebpf_result_t
ebpf_pinning_table_delete(ebpf_pinning_table_t* pinning_table, const ebpf_utf8_string_t* name)
{
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    const ebpf_utf8_string_t* existing_key = name;
    ebpf_pinning_entry_t** existing_pinning_entry;

    state = ebpf_lock_lock(&pinning_table->lock);
    return_value = ebpf_hash_table_find(
        pinning_table->hash_table, (const uint8_t*)&existing_key, (uint8_t**)&existing_pinning_entry);
    if (return_value == EBPF_SUCCESS) {
        ebpf_pinning_entry_t* entry = *existing_pinning_entry;
        return_value = ebpf_hash_table_delete(pinning_table->hash_table, (const uint8_t*)&existing_key);
        if (return_value == EBPF_SUCCESS)
            _ebpf_pinning_entry_free(entry);
    }
    ebpf_lock_unlock(&pinning_table->lock, state);

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
    ebpf_lock_state_t state = 0;
    bool lock_held = FALSE;
    uint16_t local_entry_count = 0;
    uint16_t entries_array_length = 0;
    ebpf_pinning_entry_t* local_pinning_entries = NULL;
    ebpf_utf8_string_t* next_object_name;
    ebpf_pinning_entry_t* new_entry = NULL;

    if ((entry_count == NULL) || (pinning_entries == NULL)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    state = ebpf_lock_lock(&pinning_table->lock);
    lock_held = TRUE;

    // Get output array length by finding how many entries are there in the pinning table.
    entries_array_length = (uint16_t)ebpf_hash_table_key_count(pinning_table->hash_table);

    // Exit if there are no entries.
    if (entries_array_length == 0)
        goto Exit;

    // Allocate the output array for storing the pinning entries.
    local_pinning_entries = (ebpf_pinning_entry_t*)ebpf_allocate(sizeof(ebpf_pinning_entry_t) * entries_array_length);
    if (local_pinning_entries == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

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

        if (result == EBPF_NO_MORE_KEYS) {
            // Reached end of hashtable.
            result = EBPF_SUCCESS;
            break;
        }

        if (result != EBPF_SUCCESS)
            goto Exit;

        // Skip entries that don't match the input object type.
        if (object_type != ebpf_object_get_type((*next_pinning_entry)->object)) {
            continue;
        }

        local_entry_count++;
        ebpf_assert(local_entry_count <= entries_array_length);

        // Copy the next pinning entry to a new entry in the output array.
        new_entry = &local_pinning_entries[local_entry_count - 1];
        new_entry->object = (*next_pinning_entry)->object;

        // Take reference on underlying ebpf_object.
        ebpf_object_acquire_reference(new_entry->object);

        // Duplicate pinning object name.
        result = ebpf_duplicate_utf8_string(&new_entry->name, &(*next_pinning_entry)->name);
        if (result != EBPF_SUCCESS)
            goto Exit;
    }

Exit:
    // Release lock if held.
    if (lock_held)
        ebpf_lock_unlock(&pinning_table->lock, state);

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
ebpf_pinning_entries_release(uint16_t entry_count, _In_opt_count_(entry_count) ebpf_pinning_entry_t* pinning_entries)
{
    uint16_t index;
    if (!pinning_entries)
        return;

    for (index = 0; index < entry_count; index++) {
        ebpf_pinning_entry_t* entry = &pinning_entries[index];
        ebpf_free(entry->name.value);
        entry->name.value = NULL;
        ebpf_object_release_reference(entry->object);
    }
    ebpf_free(pinning_entries);
}
