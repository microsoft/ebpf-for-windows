// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// The pinning table stores ebpf_pinning_entry_t objects in an ebpf_hash_table_t, which is designed to store fixed
// size keys and values. The pinning table uses ebpf_utf8_string_t as the key for this table, which is a variable
// sized structure with embedded pointers. As a result, ebpf_utf8_string_t structures are not directly comparable.
// To handle this case, the ebpf_hash_table_t exposes an extract method, that accepts a key and returns
// a pointer to data that can be compared or hashed. The ebpf_hash_table_t is initialized to use ebpf_utf8_string_t*
// as keys and ebpf_pinning_entry_t* as values.
// Insertion - The key is a pointer to the ebpf_utf8_string_t embedded in the ebpf_pinning_entry_t and the value is
// a pointer to the ebpf_pinning_entry_t object.
// Find/Delete - The key is a pointer to an ebpf_utf8_string_t that contains the string to search for.
// Find returns a pointer to the ebpf_pinning_entry_t object. Comparison is done based on the value pointed to by the
// key. Delete erases the entry from the ebpf_hash_table_t, but doesn't free the memory associated with the
// ebpf_pinning_entry_t.

#include "ebpf_core_structs.h"
#include "ebpf_object.h"
#include "ebpf_pinning_table.h"

#define EBPF_PINNING_TABLE_BUCKET_COUNT 64

typedef struct _ebpf_pinning_table
{
    _Guarded_by_(lock) ebpf_hash_table_t* hash_table;
    ebpf_lock_t lock;
} ebpf_pinning_table_t;

static void
_ebpf_pinning_table_extract(_In_ const uint8_t* value, _Outptr_ const uint8_t** data, _Out_ size_t* length)
{
    const ebpf_utf8_string_t* key = *(ebpf_utf8_string_t**)value;
    *data = key->value;
    *length = key->length * 8;
}

static void
_ebpf_pinning_entry_free(_Frees_ptr_opt_ ebpf_pinning_entry_t* pinning_entry)
{
    if (!pinning_entry) {
        return;
    }
    ebpf_object_release_reference(pinning_entry->object);
    ebpf_free(pinning_entry->path.value);
    ebpf_free(pinning_entry);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_allocate(ebpf_pinning_table_t** pinning_table)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    *pinning_table = ebpf_allocate(sizeof(ebpf_pinning_table_t));
    if (*pinning_table == NULL) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(*pinning_table, 0, sizeof(ebpf_pinning_table_t));

    ebpf_lock_create(&(*pinning_table)->lock);

    const ebpf_hash_table_creation_options_t options = {
        .key_size = sizeof(ebpf_utf8_string_t*),
        .value_size = sizeof(ebpf_pinning_entry_t*),
        .extract_function = _ebpf_pinning_table_extract,
        .allocate = ebpf_allocate,
        .free = ebpf_free,
    };

    return_value = ebpf_hash_table_create(&(*pinning_table)->hash_table, &options);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = EBPF_SUCCESS;
Done:
    if (return_value != EBPF_SUCCESS) {
        if ((*pinning_table)) {
            ebpf_hash_table_destroy((*pinning_table)->hash_table);
        }

        ebpf_free(*pinning_table);
        *pinning_table = NULL;
    }

    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_pinning_table_free(ebpf_pinning_table_t* pinning_table)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_utf8_string_t* key = NULL;
    if (pinning_table && pinning_table->hash_table) {
        for (;;) {
            return_value = ebpf_hash_table_next_key(pinning_table->hash_table, NULL, (uint8_t*)&key);
            if (return_value != EBPF_SUCCESS) {
                break;
            }
            ebpf_assert_success(ebpf_pinning_table_delete(pinning_table, key));
        }
        ebpf_hash_table_destroy(pinning_table->hash_table);
    }

    ebpf_free(pinning_table);
    pinning_table = NULL;
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_insert(
    ebpf_pinning_table_t* pinning_table, const ebpf_utf8_string_t* path, ebpf_core_object_t* object)
{
    EBPF_LOG_ENTRY();
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    ebpf_utf8_string_t* new_key;
    ebpf_pinning_entry_t* new_pinning_entry;

    if (path->length >= EBPF_MAX_PIN_PATH_LENGTH || path->length == 0) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    // Block embedded null terminators
    for (size_t index = 0; index < path->length; index++) {
        if (path->value[index] == 0) {
            EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
        }
    }

    new_pinning_entry = ebpf_allocate(sizeof(ebpf_pinning_entry_t));
    if (!new_pinning_entry) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    return_value = ebpf_duplicate_utf8_string(&new_pinning_entry->path, path);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    new_pinning_entry->object = object;
    ebpf_object_acquire_reference(object);
    new_key = &new_pinning_entry->path;

    state = ebpf_lock_lock(&pinning_table->lock);

    return_value = ebpf_hash_table_update(
        pinning_table->hash_table,
        (const uint8_t*)&new_key,
        (const uint8_t*)&new_pinning_entry,
        EBPF_HASH_TABLE_OPERATION_INSERT);
    if (return_value == EBPF_KEY_ALREADY_EXISTS) {
        return_value = EBPF_OBJECT_ALREADY_EXISTS;
    } else if (return_value == EBPF_SUCCESS) {
        new_pinning_entry = NULL;
        ebpf_interlocked_increment_int32(&object->pinned_path_count);
    }

    ebpf_lock_unlock(&pinning_table->lock, state);

Done:
    _ebpf_pinning_entry_free(new_pinning_entry);
    if (return_value == EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_UTF8_STRING(EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "Pinned object", *path);
    }

    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_find(
    ebpf_pinning_table_t* pinning_table, const ebpf_utf8_string_t* path, ebpf_core_object_t** object)
{
    EBPF_LOG_ENTRY();
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    const ebpf_utf8_string_t* existing_key = path;
    ebpf_pinning_entry_t** existing_pinning_entry;

    state = ebpf_lock_lock(&pinning_table->lock);
    return_value = ebpf_hash_table_find(
        pinning_table->hash_table, (const uint8_t*)&existing_key, (uint8_t**)&existing_pinning_entry);

    if (return_value == EBPF_SUCCESS) {
        *object = (*existing_pinning_entry)->object;
        ebpf_object_acquire_reference(*object);
    }

    ebpf_lock_unlock(&pinning_table->lock, state);

    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_delete(ebpf_pinning_table_t* pinning_table, const ebpf_utf8_string_t* path)
{
    EBPF_LOG_ENTRY();
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    const ebpf_utf8_string_t* existing_key = path;
    ebpf_pinning_entry_t** existing_pinning_entry;
    ebpf_pinning_entry_t* entry = NULL;

    state = ebpf_lock_lock(&pinning_table->lock);
    return_value = ebpf_hash_table_find(
        pinning_table->hash_table, (const uint8_t*)&existing_key, (uint8_t**)&existing_pinning_entry);
    if (return_value == EBPF_SUCCESS) {
        entry = *existing_pinning_entry;
        return_value = ebpf_hash_table_delete(pinning_table->hash_table, (const uint8_t*)&existing_key);
        // If unable to remove the entry from the table, don't delete it.
        if (return_value != EBPF_SUCCESS) {
            entry = NULL;
        }
    }
    ebpf_lock_unlock(&pinning_table->lock, state);

    // Log the free of the path before freeing the entry (which may contain the path).
    if (return_value == EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_UTF8_STRING(EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "Unpinned object", *path);
    }

    if (entry != NULL) {
        ebpf_interlocked_decrement_int32(&entry->object->pinned_path_count);
        _ebpf_pinning_entry_free(entry);
    }

    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_enumerate_entries(
    _Inout_ ebpf_pinning_table_t* pinning_table,
    ebpf_object_type_t object_type,
    _Out_ uint16_t* entry_count,
    _Outptr_result_buffer_maybenull_(*entry_count) ebpf_pinning_entry_t** pinning_entries)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state = 0;
    bool lock_held = FALSE;
    uint16_t local_entry_count = 0;
    uint16_t entries_array_length = 0;
    ebpf_pinning_entry_t* local_pinning_entries = NULL;
    ebpf_utf8_string_t* next_object_path;
    ebpf_pinning_entry_t* new_entry = NULL;

    ebpf_assert(entry_count);
    ebpf_assert(pinning_entries);

    state = ebpf_lock_lock(&pinning_table->lock);
    lock_held = TRUE;

    // Get output array length by finding how many entries are there in the pinning table.
    entries_array_length = (uint16_t)ebpf_hash_table_key_count(pinning_table->hash_table);

    // Exit if there are no entries.
    if (entries_array_length == 0) {
        goto Exit;
    }

    // Allocate the output array for storing the pinning entries.
    local_pinning_entries = (ebpf_pinning_entry_t*)ebpf_allocate(sizeof(ebpf_pinning_entry_t) * entries_array_length);
    if (local_pinning_entries == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Loop through the entries in the hashtable.
    next_object_path = NULL;
    for (;;) {
        ebpf_pinning_entry_t** next_pinning_entry = NULL;

        // Find next pinning entry, if any.
        result = ebpf_hash_table_next_key_and_value(
            pinning_table->hash_table,
            (const uint8_t*)((next_object_path == NULL) ? NULL : &next_object_path),
            (uint8_t*)&next_object_path,
            (uint8_t**)&next_pinning_entry);

        if (result == EBPF_NO_MORE_KEYS) {
            // Reached end of hashtable.
            result = EBPF_SUCCESS;
            break;
        }

        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

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

        // Duplicate pinning object path.
        result = ebpf_duplicate_utf8_string(&new_entry->path, &(*next_pinning_entry)->path);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    }

Exit:
    // Release lock if held.
    if (lock_held) {
        ebpf_lock_unlock(&pinning_table->lock, state);
    }

    if (result != EBPF_SUCCESS) {
        ebpf_pinning_entries_release(local_entry_count, local_pinning_entries);
        local_entry_count = 0;
        local_pinning_entries = NULL;
    }

    // Set output parameters.
    *entry_count = local_entry_count;
    *pinning_entries = local_pinning_entries;

    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_get_next_path(
    _Inout_ ebpf_pinning_table_t* pinning_table,
    ebpf_object_type_t object_type,
    _In_ const ebpf_utf8_string_t* start_path,
    _Inout_ ebpf_utf8_string_t* next_path)
{
    EBPF_LOG_ENTRY();
    if ((pinning_table == NULL) || (start_path == NULL) || (next_path == NULL)) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    const uint8_t* previous_key = (start_path->length == 0) ? NULL : (const uint8_t*)&start_path;

    ebpf_lock_state_t state = ebpf_lock_lock(&pinning_table->lock);

    ebpf_result_t result;
    ebpf_pinning_entry_t** next_pinning_entry = NULL;

    for (;;) {
        // Get the next entry in the table.
        ebpf_utf8_string_t* next_object_path;
        result = ebpf_hash_table_next_key_and_value(
            pinning_table->hash_table, previous_key, (uint8_t*)&next_object_path, (uint8_t**)&next_pinning_entry);
        if (result != EBPF_SUCCESS) {
            break;
        }

        // See if the entry matches the object type the caller is interested in.
        if (object_type == ebpf_object_get_type((*next_pinning_entry)->object)) {
            if (next_path->length < (*next_pinning_entry)->path.length) {
                result = EBPF_INSUFFICIENT_BUFFER;
            } else {
                next_path->length = (*next_pinning_entry)->path.length;
                memcpy(next_path->value, (*next_pinning_entry)->path.value, next_path->length);
                result = EBPF_SUCCESS;
            }
            break;
        }
        previous_key = (uint8_t*)&next_object_path;
    }

    ebpf_lock_unlock(&pinning_table->lock, state);
    EBPF_RETURN_RESULT(result);
}

void
ebpf_pinning_entries_release(uint16_t entry_count, _In_opt_count_(entry_count) ebpf_pinning_entry_t* pinning_entries)
{
    EBPF_LOG_ENTRY();
    uint16_t index;
    if (!pinning_entries) {
        EBPF_RETURN_VOID();
    }

    for (index = 0; index < entry_count; index++) {
        ebpf_pinning_entry_t* entry = &pinning_entries[index];
        ebpf_free(entry->path.value);
        entry->path.value = NULL;
        ebpf_object_release_reference(entry->object);
    }
    ebpf_free(pinning_entries);
    EBPF_RETURN_VOID();
}
