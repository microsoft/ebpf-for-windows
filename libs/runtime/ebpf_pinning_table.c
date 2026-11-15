// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_PINNING_TABLE

#include "ebpf_core_structs.h"
#include "ebpf_hash_table.h"
#include "ebpf_object.h"
#include "ebpf_pinning_table.h"
#include "ebpf_tracelog.h"

#if defined(EBPF_RUNTIME_TEST_INSTRUMENTATION)
#include "ebpf_object_test.h"
#define EBPF_PINNING_TEST_FAIL(point) ebpf_object_test_invoke(point, NULL)

static void*
_ebpf_pinning_test_allocate_hash(size_t size, uint32_t tag)
{
    if (EBPF_PINNING_TEST_FAIL(EBPF_OBJECT_TEST_PIN_HASH_ALLOCATION)) {
        return NULL;
    }
    return ebpf_allocate_with_tag(size, tag);
}
#else
#define EBPF_PINNING_TEST_FAIL(point) false
#endif

typedef struct _ebpf_pinning_table
{
    _Guarded_by_(lock) ebpf_hash_table_t* hash_table;
    ebpf_lock_t lock;
    uint64_t next_cookie;
} ebpf_pinning_table_t;

#if defined(EBPF_RUNTIME_TEST_INSTRUMENTATION)
void
ebpf_pinning_table_test_set_cookie_counter(_Inout_ ebpf_pinning_table_t* table, uint64_t value)
{
    ebpf_lock_state_t state = ebpf_lock_lock(&table->lock);
    table->next_cookie = value;
    ebpf_lock_unlock(&table->lock, state);
}
#endif

typedef struct _ebpf_scoped_pinning_entry
{
    ebpf_pinning_entry_t entry;
    cxplat_utf8_string_t key;
    uint64_t cookie;
    // The visible path aliases the owned GUID || path key; snapshots duplicate only the visible tail.
    uint8_t key_bytes[1];
} ebpf_scoped_pinning_entry_t;

typedef struct _ebpf_pinning_filter
{
    const GUID* namespace_id;
    ebpf_object_type_t object_type;
} ebpf_pinning_filter_t;

static void
_ebpf_pinning_table_extract(_In_ const uint8_t* value, _Outptr_ const uint8_t** data, _Out_ size_t* length)
{
    const cxplat_utf8_string_t* key = *(const cxplat_utf8_string_t* const*)value;
    *data = key->value;
    *length = key->length * 8;
}

static ebpf_result_t
_ebpf_pinning_table_make_key(
    _In_ const GUID* namespace_id,
    _In_ const cxplat_utf8_string_t* path,
    bool allow_empty,
    _Out_ cxplat_utf8_string_t* key,
    _Out_writes_(sizeof(GUID) + EBPF_MAX_PIN_PATH_LENGTH) uint8_t* bytes)
{
    if (namespace_id == NULL || path->length >= EBPF_MAX_PIN_PATH_LENGTH || (!allow_empty && path->length == 0) ||
        (path->length != 0 && path->value == NULL)) {
        return EBPF_INVALID_ARGUMENT;
    }
    for (size_t index = 0; index < path->length; index++) {
        if (path->value[index] == 0) {
            return EBPF_INVALID_ARGUMENT;
        }
    }
    size_t length;
    ebpf_result_t result = ebpf_safe_size_t_add(sizeof(GUID), path->length, &length);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    size_t bits;
    result = ebpf_safe_size_t_multiply(length, 8, &bits);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    memcpy(bytes, namespace_id, sizeof(GUID));
    if (path->length != 0) {
        memcpy(bytes + sizeof(GUID), path->value, path->length);
    }
    key->value = bytes;
    key->length = length;
    return EBPF_SUCCESS;
}

static void
_ebpf_pinning_entry_free(_Frees_ptr_opt_ ebpf_scoped_pinning_entry_t* entry)
{
    if (entry != NULL) {
        EBPF_OBJECT_RELEASE_REFERENCE_USER(entry->entry.object);
        ebpf_free(entry);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_allocate(ebpf_pinning_table_t** pinning_table)
{
    *pinning_table = NULL;
    if (EBPF_PINNING_TEST_FAIL(EBPF_OBJECT_TEST_PIN_TABLE_ALLOCATION)) {
        return EBPF_NO_MEMORY;
    }
    *pinning_table = ebpf_allocate_with_tag(sizeof(ebpf_pinning_table_t), EBPF_POOL_TAG_PINNING);
    if (*pinning_table == NULL) {
        return EBPF_NO_MEMORY;
    }
    memset(*pinning_table, 0, sizeof(ebpf_pinning_table_t));
    ebpf_lock_create(&(*pinning_table)->lock);
    const ebpf_hash_table_creation_options_t options = {
        .key_size = sizeof(cxplat_utf8_string_t*),
        .value_size = sizeof(ebpf_scoped_pinning_entry_t*),
        .extract_function = _ebpf_pinning_table_extract,
#if defined(EBPF_RUNTIME_TEST_INSTRUMENTATION)
        .allocate = _ebpf_pinning_test_allocate_hash,
#else
        .allocate = ebpf_allocate_with_tag,
#endif
        .allocation_tag = EBPF_POOL_TAG_PINNING,
        .free = ebpf_free,
    };
    ebpf_result_t result = ebpf_hash_table_create(&(*pinning_table)->hash_table, &options);
    if (result != EBPF_SUCCESS) {
        ebpf_free(*pinning_table);
        *pinning_table = NULL;
    }
    return result;
}

void
ebpf_pinning_table_free(ebpf_pinning_table_t* pinning_table)
{
    if (pinning_table == NULL) {
        return;
    }
    if (pinning_table->hash_table != NULL) {
        for (;;) {
            cxplat_utf8_string_t* key = NULL;
            ebpf_scoped_pinning_entry_t** entry;
            ebpf_result_t result =
                ebpf_hash_table_next_key_and_value(pinning_table->hash_table, NULL, (uint8_t*)&key, (uint8_t**)&entry);
            if (result == EBPF_NO_MORE_KEYS) {
                break;
            }
            ebpf_assert_success(result);
            ebpf_scoped_pinning_entry_t* removed_entry = *entry;
            ebpf_assert_success(ebpf_hash_table_delete(pinning_table->hash_table, NULL, (const uint8_t*)&key));
            ebpf_interlocked_decrement_int32(&removed_entry->entry.object->pinned_path_count);
            _ebpf_pinning_entry_free(removed_entry);
        }
        ebpf_hash_table_destroy(pinning_table->hash_table);
    }
    ebpf_free(pinning_table);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_insert(
    ebpf_pinning_table_t* pinning_table,
    _In_ const GUID* namespace_id,
    const cxplat_utf8_string_t* path,
    ebpf_core_object_t* object)
{
    return ebpf_pinning_table_insert_with_cookie(pinning_table, namespace_id, path, object, NULL);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_insert_with_cookie(
    ebpf_pinning_table_t* pinning_table,
    _In_ const GUID* namespace_id,
    const cxplat_utf8_string_t* path,
    ebpf_core_object_t* object,
    _Out_opt_ uint64_t* cookie)
{
    if (namespace_id == NULL || memcmp(namespace_id, &object->namespace_id, sizeof(GUID)) != 0) {
        return EBPF_INVALID_ARGUMENT;
    }
    uint8_t key_bytes[sizeof(GUID) + EBPF_MAX_PIN_PATH_LENGTH];
    cxplat_utf8_string_t key;
    ebpf_result_t result = _ebpf_pinning_table_make_key(namespace_id, path, false, &key, key_bytes);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    size_t allocation_size;
    result = ebpf_safe_size_t_add(EBPF_OFFSET_OF(ebpf_scoped_pinning_entry_t, key_bytes), key.length, &allocation_size);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    if (EBPF_PINNING_TEST_FAIL(EBPF_OBJECT_TEST_PIN_ENTRY_ALLOCATION)) {
        return EBPF_NO_MEMORY;
    }
    ebpf_scoped_pinning_entry_t* entry = ebpf_allocate_with_tag(allocation_size, EBPF_POOL_TAG_PINNING);
    if (entry == NULL) {
        return EBPF_NO_MEMORY;
    }
    memcpy(entry->key_bytes, key.value, key.length);
    entry->key.value = entry->key_bytes;
    entry->key.length = key.length;
    entry->entry.path.value = entry->key_bytes + sizeof(GUID);
    entry->entry.path.length = path->length;
    entry->entry.object = object;
    const cxplat_utf8_string_t* stored_key = &entry->key;
    ebpf_lock_state_t state = ebpf_lock_lock(&pinning_table->lock);
    if (pinning_table->next_cookie == UINT64_MAX) {
        ebpf_lock_unlock(&pinning_table->lock, state);
        ebpf_free(entry);
        return EBPF_ARITHMETIC_OVERFLOW;
    }
    entry->cookie = ++pinning_table->next_cookie;
    result = ebpf_hash_table_update(
        pinning_table->hash_table,
        NULL,
        (const uint8_t*)&stored_key,
        (const uint8_t*)&entry,
        EBPF_HASH_TABLE_OPERATION_INSERT);
    if (result == EBPF_SUCCESS) {
        if (cookie != NULL) {
            *cookie = entry->cookie;
        }
        EBPF_OBJECT_ACQUIRE_REFERENCE_USER(object);
        ebpf_interlocked_increment_int32(&object->pinned_path_count);
        entry = NULL;
    } else if (result == EBPF_KEY_ALREADY_EXISTS) {
        result = EBPF_OBJECT_ALREADY_EXISTS;
    }
    ebpf_lock_unlock(&pinning_table->lock, state);
    ebpf_free(entry);
    if (result == EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_UTF8_STRING(EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "Pinned object", path);
    }
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_find(
    ebpf_pinning_table_t* pinning_table,
    _In_ const GUID* namespace_id,
    const cxplat_utf8_string_t* path,
    ebpf_core_object_t** object)
{
    *object = NULL;
    uint8_t key_bytes[sizeof(GUID) + EBPF_MAX_PIN_PATH_LENGTH];
    cxplat_utf8_string_t key;
    ebpf_result_t result = _ebpf_pinning_table_make_key(namespace_id, path, false, &key, key_bytes);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    const cxplat_utf8_string_t* key_pointer = &key;
    ebpf_scoped_pinning_entry_t** entry;
    ebpf_lock_state_t state = ebpf_lock_lock(&pinning_table->lock);
    result = ebpf_hash_table_find(pinning_table->hash_table, (const uint8_t*)&key_pointer, (uint8_t**)&entry);
    if (result == EBPF_SUCCESS) {
        *object = (*entry)->entry.object;
        EBPF_OBJECT_ACQUIRE_REFERENCE(*object);
    }
    ebpf_lock_unlock(&pinning_table->lock, state);
    return result;
}

static ebpf_result_t
_ebpf_pinning_table_delete(
    ebpf_pinning_table_t* pinning_table,
    _In_ const GUID* namespace_id,
    const cxplat_utf8_string_t* path,
    _In_opt_ const ebpf_core_object_t* expected_object,
    uint64_t cookie)
{
    uint8_t key_bytes[sizeof(GUID) + EBPF_MAX_PIN_PATH_LENGTH];
    cxplat_utf8_string_t key;
    ebpf_result_t result = _ebpf_pinning_table_make_key(namespace_id, path, false, &key, key_bytes);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    const cxplat_utf8_string_t* key_pointer = &key;
    ebpf_scoped_pinning_entry_t** entry;
    ebpf_scoped_pinning_entry_t* removed_entry = NULL;
    ebpf_lock_state_t state = ebpf_lock_lock(&pinning_table->lock);
    result = ebpf_hash_table_find(pinning_table->hash_table, (const uint8_t*)&key_pointer, (uint8_t**)&entry);
    if (result == EBPF_SUCCESS) {
        if ((expected_object != NULL && (*entry)->entry.object != expected_object) ||
            (cookie != 0 && (*entry)->cookie != cookie)) {
            result = EBPF_KEY_NOT_FOUND;
        } else {
            removed_entry = *entry;
            result = ebpf_hash_table_delete(pinning_table->hash_table, NULL, (const uint8_t*)&key_pointer);
            if (result != EBPF_SUCCESS) {
                removed_entry = NULL;
            }
        }
    }
    ebpf_lock_unlock(&pinning_table->lock, state);
    if (removed_entry != NULL) {
        EBPF_LOG_MESSAGE_UTF8_STRING(EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "Unpinned object", path);
        ebpf_interlocked_decrement_int32(&removed_entry->entry.object->pinned_path_count);
        _ebpf_pinning_entry_free(removed_entry);
    }
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_delete(
    ebpf_pinning_table_t* pinning_table, _In_ const GUID* namespace_id, const cxplat_utf8_string_t* path)
{
    return _ebpf_pinning_table_delete(pinning_table, namespace_id, path, NULL, 0);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_delete_if_matches(
    ebpf_pinning_table_t* pinning_table,
    _In_ const GUID* namespace_id,
    const cxplat_utf8_string_t* path,
    _In_ const ebpf_core_object_t* expected_object)
{
    if (expected_object == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }
    return _ebpf_pinning_table_delete(pinning_table, namespace_id, path, expected_object, 0);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_delete_with_cookie(
    ebpf_pinning_table_t* pinning_table,
    _In_ const GUID* namespace_id,
    const cxplat_utf8_string_t* path,
    _In_ const ebpf_core_object_t* expected_object,
    uint64_t cookie)
{
    if (cookie == 0 || expected_object == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }
    return _ebpf_pinning_table_delete(pinning_table, namespace_id, path, expected_object, cookie);
}

static bool
_ebpf_pinning_table_match(_In_ void* filter_context, _In_ const uint8_t* key, _In_ const uint8_t* value)
{
    const ebpf_pinning_filter_t* filter = filter_context;
    const ebpf_scoped_pinning_entry_t* entry = *(ebpf_scoped_pinning_entry_t* const*)value;
    UNREFERENCED_PARAMETER(key);
    return memcmp(entry->key.value, filter->namespace_id, sizeof(GUID)) == 0 &&
           (filter->object_type == EBPF_OBJECT_UNKNOWN || entry->entry.object->type == filter->object_type);
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_enumerate_entries(
    _Inout_ ebpf_pinning_table_t* pinning_table,
    _In_ const GUID* namespace_id,
    ebpf_object_type_t object_type,
    _Out_ uint16_t* entry_count,
    _Outptr_result_buffer_maybenull_(*entry_count) ebpf_pinning_entry_t** pinning_entries)
{
    *entry_count = 0;
    *pinning_entries = NULL;
    if (namespace_id == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_pinning_filter_t filter = {.namespace_id = namespace_id, .object_type = object_type};
    uint32_t visible_count = 0;
    uint16_t copied_count = 0;
    ebpf_pinning_entry_t* entries = NULL;
    ebpf_result_t result;
    ebpf_lock_state_t state = ebpf_lock_lock(&pinning_table->lock);
    cxplat_utf8_string_t* key = NULL;
    for (;;) {
        ebpf_scoped_pinning_entry_t** entry;
        result = ebpf_hash_table_next_key_and_value(
            pinning_table->hash_table, key == NULL ? NULL : (const uint8_t*)&key, (uint8_t*)&key, (uint8_t**)&entry);
        if (result == EBPF_NO_MORE_KEYS) {
            result = EBPF_SUCCESS;
            break;
        }
        if (result != EBPF_SUCCESS) {
            goto Done;
        }
        if (_ebpf_pinning_table_match(&filter, (const uint8_t*)&key, (const uint8_t*)entry)) {
            if (++visible_count > UINT16_MAX) {
                result = EBPF_ARITHMETIC_OVERFLOW;
                goto Done;
            }
        }
    }
    if (visible_count == 0) {
        goto Done;
    }
    size_t allocation_size;
    result = ebpf_safe_size_t_multiply(visible_count, sizeof(*entries), &allocation_size);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }
    if (EBPF_PINNING_TEST_FAIL(EBPF_OBJECT_TEST_PIN_SNAPSHOT_ALLOCATION)) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    entries = ebpf_allocate_with_tag(allocation_size, EBPF_POOL_TAG_PINNING);
    if (entries == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    memset(entries, 0, allocation_size);
    key = NULL;
    for (;;) {
        ebpf_scoped_pinning_entry_t** entry;
        result = ebpf_hash_table_next_key_and_value(
            pinning_table->hash_table, key == NULL ? NULL : (const uint8_t*)&key, (uint8_t*)&key, (uint8_t**)&entry);
        if (result == EBPF_NO_MORE_KEYS) {
            result = EBPF_SUCCESS;
            break;
        }
        if (result != EBPF_SUCCESS) {
            goto Done;
        }
        if (!_ebpf_pinning_table_match(&filter, (const uint8_t*)&key, (const uint8_t*)entry)) {
            continue;
        }
        result = EBPF_PINNING_TEST_FAIL(EBPF_OBJECT_TEST_PIN_SNAPSHOT_PATH_ALLOCATION)
                     ? EBPF_NO_MEMORY
                     : ebpf_duplicate_utf8_string(&entries[copied_count].path, &(*entry)->entry.path);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }
        entries[copied_count].object = (*entry)->entry.object;
        EBPF_OBJECT_ACQUIRE_REFERENCE(entries[copied_count].object);
        copied_count++;
    }
Done:
    ebpf_lock_unlock(&pinning_table->lock, state);
    if (result != EBPF_SUCCESS) {
        ebpf_pinning_entries_release(copied_count, entries);
    } else {
        *entry_count = copied_count;
        *pinning_entries = entries;
    }
    return result;
}

static int
_ebpf_pinning_table_compare(_In_ const uint8_t* key1, _In_ const uint8_t* key2)
{
    const cxplat_utf8_string_t* first = *(const cxplat_utf8_string_t* const*)key1;
    const cxplat_utf8_string_t* second = *(const cxplat_utf8_string_t* const*)key2;
    size_t min_length = first->length < second->length ? first->length : second->length;
    int result = memcmp(first->value, second->value, min_length);
    if (result != 0) {
        return result;
    }
    return first->length < second->length ? -1 : first->length > second->length ? 1 : 0;
}

_Must_inspect_result_ ebpf_result_t
ebpf_pinning_table_get_next_path(
    _Inout_ ebpf_pinning_table_t* pinning_table,
    _In_ const GUID* namespace_id,
    _Inout_ ebpf_object_type_t* object_type,
    _In_ const cxplat_utf8_string_t* start_path,
    _Inout_ cxplat_utf8_string_t* next_path)
{
    if (pinning_table == NULL || namespace_id == NULL || object_type == NULL || start_path == NULL ||
        next_path == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }
    uint8_t key_bytes[sizeof(GUID) + EBPF_MAX_PIN_PATH_LENGTH];
    cxplat_utf8_string_t key;
    ebpf_result_t result = _ebpf_pinning_table_make_key(namespace_id, start_path, true, &key, key_bytes);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    const cxplat_utf8_string_t* key_pointer = &key;
    ebpf_pinning_filter_t filter = {.namespace_id = namespace_id, .object_type = *object_type};
    ebpf_lock_state_t state = ebpf_lock_lock(&pinning_table->lock);
    cxplat_utf8_string_t* next_key;
    ebpf_scoped_pinning_entry_t** entry;
    result = ebpf_hash_table_next_key_and_value_sorted(
        pinning_table->hash_table,
        (const uint8_t*)&key_pointer,
        _ebpf_pinning_table_compare,
        &filter,
        _ebpf_pinning_table_match,
        (uint8_t*)&next_key,
        (uint8_t**)&entry);
    if (result == EBPF_SUCCESS) {
        if (next_path->length < (*entry)->entry.path.length) {
            result = EBPF_INSUFFICIENT_BUFFER;
        } else {
            next_path->length = (*entry)->entry.path.length;
            memcpy(next_path->value, (*entry)->entry.path.value, next_path->length);
            *object_type = (*entry)->entry.object->type;
        }
    }
    ebpf_lock_unlock(&pinning_table->lock, state);
    return result;
}

void
ebpf_pinning_entries_release(uint16_t entry_count, _In_opt_count_(entry_count) ebpf_pinning_entry_t* pinning_entries)
{
    if (pinning_entries == NULL) {
        return;
    }
    for (uint16_t index = 0; index < entry_count; index++) {
        ebpf_free(pinning_entries[index].path.value);
        EBPF_OBJECT_RELEASE_REFERENCE(pinning_entries[index].object);
    }
    ebpf_free(pinning_entries);
}
