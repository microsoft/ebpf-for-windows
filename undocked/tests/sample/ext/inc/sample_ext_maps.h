// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

// Sample extension extensible map implementations.
// Common implementation to be included both in the sample extension driver and unit tests.

#include "ebpf_api.h"
#include "ebpf_extension.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_nethooks.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"
#include "sample_ext_maps.h"
#include "sample_ext_program_info.h"

#define EBPF_SAMPLE_MAP_PROVIDER_GUID                                                  \
    {                                                                                  \
        0xf788ef4b, 0x207d, 0x4dc4, { 0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c } \
    }

extern uint32_t map_pool_tag;

typedef struct _sample_core_map
{
    uint32_t map_type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
} sample_core_map_t;

typedef struct _sample_base_array_map
{
    sample_core_map_t core;
    uint8_t* data;
} sample_base_array_map_t;

static inline ebpf_result_t
_sample_array_map_find_entry_common(
    _In_ const sample_base_array_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    _Outptr_ uint8_t** value,
    uint32_t flags)
{
    UNREFERENCED_PARAMETER(flags);

    if (key == NULL || value == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }
    if (flags & EBPF_MAP_FIND_FLAG_DELETE) {
        // Deletion is not supported for array map.
        return EBPF_INVALID_ARGUMENT;
    }

    if (!(flags & EBPF_MAP_FLAG_HELPER) && key_size != map->core.key_size) {
        return EBPF_INVALID_ARGUMENT;
    }

    // In an array map, the key is an index.
    uint32_t index = *(uint32_t*)key;
    if (index >= map->core.max_entries) {
        return EBPF_OBJECT_NOT_FOUND;
    }

    *value = map->data + ((size_t)index * map->core.value_size);
    return EBPF_SUCCESS;
}

static ebpf_result_t
_sample_array_map_update_entry_common(
    _In_ const sample_base_array_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    ebpf_map_option_t option,
    uint32_t flags)
{
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(option);

    if (key == NULL || value == NULL || option == EBPF_NOEXIST) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (!(flags & EBPF_MAP_FLAG_HELPER) && (key_size != map->core.key_size || value_size != map->core.value_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    // In an array map, the key is an index.
    uint32_t index = *(uint32_t*)key;
    if (index >= map->core.max_entries) {
        return EBPF_OBJECT_NOT_FOUND;
    }

    // Update existing entry
    memcpy(map->data + ((size_t)index * map->core.value_size), value, map->core.value_size);
    return EBPF_SUCCESS;
}

static ebpf_result_t
_sample_array_map_delete_entry_common(
    _In_ const sample_base_array_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, uint32_t flags)
{
    UNREFERENCED_PARAMETER(flags);

    if (map == NULL || key == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (!(flags & EBPF_MAP_FLAG_HELPER) && key_size != map->core.key_size) {
        return EBPF_INVALID_ARGUMENT;
    }

    // In an array map, the key is an index.
    uint32_t index = *(uint32_t*)key;
    if (index >= map->core.max_entries) {
        return EBPF_OBJECT_NOT_FOUND;
    }
    memset(map->data + ((size_t)index * map->core.value_size), 0, map->core.value_size);
    return EBPF_SUCCESS;
}

static ebpf_result_t
_sample_array_map_get_next_key_and_value_common(
    _In_ const sample_base_array_map_t* map,
    size_t key_size,
    _In_opt_ const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value)
{
    ebpf_result_t result = EBPF_NO_MORE_KEYS;
    if (map == NULL || next_key == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (key_size != map->core.key_size) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (previous_key != NULL) {
        uint32_t prev_index = *(uint32_t*)previous_key;
        if (prev_index + 1 < map->core.max_entries) {
            uint32_t next_index = prev_index + 1;
            memcpy(next_key, &next_index, map->core.key_size);
            if (next_value != NULL) {
                *next_value = map->data + ((size_t)next_index * map->core.value_size);
            }
            result = EBPF_SUCCESS;
        } else {
            result = EBPF_NO_MORE_KEYS;
        }
    } else {
        // Return first key if previous_key is NULL.
        uint32_t first_index = 0;
        memcpy(next_key, &first_index, map->core.key_size);
        if (next_value != NULL) {
            *next_value = map->data;
        }
        result = EBPF_SUCCESS;
    }

    return result;
}

// Hash bucket entry in array format
typedef struct _sample_hash_bucket_entry
{
    uint8_t* key_value_data; // Key followed by value in contiguous memory
} sample_hash_bucket_entry_t;

typedef struct _sample_hash_bucket
{
    EX_SPIN_LOCK lock;                   // Reader-writer lock for this bucket
    sample_hash_bucket_entry_t* entries; // Array of entries
    uint32_t capacity;                   // Current capacity of entries array
    uint32_t count;                      // Number of entries currently stored
} sample_hash_bucket_t;

typedef struct _sample_base_hash_map
{
    sample_core_map_t core;
    uint32_t entry_count;
    sample_hash_bucket_t* buckets; // Array of hash buckets
    uint32_t bucket_count;
} sample_base_hash_map_t;

static uint32_t
_sample_map_hash(const uint8_t* key, uint32_t key_size, uint32_t bucket_count)
{
    uint32_t hash = 0;
    for (uint32_t i = 0; i < key_size; i++) {
        hash = hash * 31 + key[i];
    }
    return hash % bucket_count;
}

static int32_t
_sample_hash_map_find_entry_index_internal(sample_hash_bucket_t* bucket, const uint8_t* key, uint32_t key_size)
{
    // Assumes bucket is already locked (shared or exclusive)
    for (uint32_t i = 0; i < bucket->count; i++) {
        if (bucket->entries[i].key_value_data != NULL &&
            memcmp(bucket->entries[i].key_value_data, key, key_size) == 0) {
            return (int32_t)i;
        }
    }
    return -1; // Not found
}

static ebpf_result_t
_sample_hash_map_get_next_key_and_value_common(
    _In_ sample_base_hash_map_t* map,
    size_t key_size,
    _In_ const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value)
{
    bool found_previous = (previous_key == NULL);
    KIRQL old_irql;

    UNREFERENCED_PARAMETER(key_size);

    // Iterate through all buckets and their entries
    for (uint32_t i = 0; i < map->bucket_count; i++) {
        sample_hash_bucket_t* bucket = &map->buckets[i];

        // Acquire shared lock for read access
        old_irql = ExAcquireSpinLockShared(&bucket->lock);

        for (uint32_t j = 0; j < bucket->count; j++) {
            if (bucket->entries[j].key_value_data != NULL) {
                if (found_previous) {
                    // Return the first entry after previous_key
                    memcpy(next_key, bucket->entries[j].key_value_data, map->core.key_size);
                    if (next_value != NULL) {
                        *next_value = bucket->entries[j].key_value_data + map->core.key_size;
                    }
                    ExReleaseSpinLockShared(&bucket->lock, old_irql);
                    return EBPF_SUCCESS;
                }
                if (previous_key != NULL &&
                    memcmp(bucket->entries[j].key_value_data, previous_key, map->core.key_size) == 0) {
                    found_previous = true;
                }
            }
        }

        ExReleaseSpinLockShared(&bucket->lock, old_irql);
    }

    return EBPF_NO_MORE_KEYS;
}

static ebpf_result_t
_sample_hash_map_delete_entry_common(
    ebpf_map_client_dispatch_table_t* client_dispatch_table,
    _In_ sample_base_hash_map_t* map,
    size_t key_size,
    _In_ const uint8_t* key,
    uint32_t flags)
{
    uint32_t hash;
    sample_hash_bucket_t* bucket;
    int32_t entry_index;
    KIRQL old_irql;
    ebpf_result_t result = EBPF_SUCCESS;

    UNREFERENCED_PARAMETER(key_size);
    UNREFERENCED_PARAMETER(flags);

    hash = _sample_map_hash(key, map->core.key_size, map->bucket_count);
    bucket = &map->buckets[hash];

    // Acquire exclusive lock for write access
    old_irql = ExAcquireSpinLockExclusive(&bucket->lock);

    entry_index = _sample_hash_map_find_entry_index_internal(bucket, key, map->core.key_size);

    if (entry_index >= 0) {
        // Free the key-value data
        client_dispatch_table->epoch_free(bucket->entries[entry_index].key_value_data);

        // Move the last entry to fill the gap (if not already the last entry)
        if (entry_index < (int32_t)(bucket->count - 1)) {
            bucket->entries[entry_index] = bucket->entries[bucket->count - 1];
        }

        // Clear the last entry and decrement count
        bucket->entries[bucket->count - 1].key_value_data = NULL;
        bucket->count--;
        map->entry_count--;
    }

    ExReleaseSpinLockExclusive(&bucket->lock, old_irql);
    return result;
}

static ebpf_result_t
_sample_hash_map_find_entry_common(
    ebpf_map_client_dispatch_table_t* client_dispatch_table,
    _In_ sample_base_hash_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    _Outptr_ uint8_t** value,
    uint32_t flags)
{
    ebpf_result_t result = EBPF_KEY_NOT_FOUND;
    uint32_t hash;
    sample_hash_bucket_t* bucket;
    int32_t entry_index;
    KIRQL old_irql;

    *value = NULL;

    if (key == NULL || value == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    hash = _sample_map_hash(key, map->core.key_size, map->bucket_count);
    bucket = &map->buckets[hash];

    // Acquire shared lock for read access
    old_irql = ExAcquireSpinLockShared(&bucket->lock);

    entry_index = _sample_hash_map_find_entry_index_internal(bucket, key, map->core.key_size);
    if (entry_index >= 0) {
        *value = bucket->entries[entry_index].key_value_data + map->core.key_size; // Value follows key
        result = EBPF_SUCCESS;
    }

    ExReleaseSpinLockShared(&bucket->lock, old_irql);

    if (result == EBPF_SUCCESS && (flags & EBPF_MAP_FIND_FLAG_DELETE)) {
        return _sample_hash_map_delete_entry_common(client_dispatch_table, map, key_size, key, flags);
    }

    return result;
}

static ebpf_result_t
_sample_hash_map_update_entry_common(
    ebpf_map_client_dispatch_table_t* client_dispatch_table,
    _In_ sample_base_hash_map_t* map,
    size_t key_size,
    _In_ const uint8_t* key,
    size_t value_size,
    _In_ const uint8_t* value,
    ebpf_map_option_t option,
    uint32_t flags)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t hash;
    sample_hash_bucket_t* bucket;
    int32_t entry_index;
    KIRQL old_irql;
    uint32_t entry_size;
    uint8_t* key_value_data = NULL;

    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(value_size);
    UNREFERENCED_PARAMETER(key_size);

    if (key == NULL || value == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    hash = _sample_map_hash(key, map->core.key_size, map->bucket_count);
    bucket = &map->buckets[hash];
    entry_size = map->core.key_size + map->core.value_size;

    // Acquire exclusive lock for write access
    old_irql = ExAcquireSpinLockExclusive(&bucket->lock);

    entry_index = _sample_hash_map_find_entry_index_internal(bucket, key, map->core.key_size);

    // Check option constraints
    if (option == EBPF_NOEXIST && entry_index >= 0) {
        result = EBPF_KEY_ALREADY_EXISTS;
        goto Exit;
    }
    if (option == EBPF_EXIST && entry_index < 0) {
        result = EBPF_KEY_NOT_FOUND;
        goto Exit;
    }

    if (entry_index >= 0) {
        // Update existing entry in place
        memcpy(bucket->entries[entry_index].key_value_data + map->core.key_size, value, map->core.value_size);
        goto Exit;
    }

    // Create new entry
    if (map->entry_count >= map->core.max_entries) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Allocate key-value data
    key_value_data = (uint8_t*)client_dispatch_table->epoch_allocate_with_tag(entry_size, map_pool_tag);
    if (key_value_data == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Copy key and value
    memcpy(key_value_data, key, map->core.key_size);
    memcpy(key_value_data + map->core.key_size, value, map->core.value_size);

    // Check if bucket needs expansion
    if (bucket->count >= bucket->capacity) {
        // Need to expand the bucket array
        uint32_t new_capacity = bucket->capacity + 10;
        sample_hash_bucket_entry_t* new_entries =
            (sample_hash_bucket_entry_t*)client_dispatch_table->epoch_allocate_cache_aligned_with_tag(
                sizeof(sample_hash_bucket_entry_t) * new_capacity, map_pool_tag);

        if (new_entries == NULL) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        // Copy old entries to new array
        if (bucket->entries != NULL && bucket->count > 0) {
            memcpy(new_entries, bucket->entries, sizeof(sample_hash_bucket_entry_t) * bucket->count);
            client_dispatch_table->epoch_free_cache_aligned(bucket->entries);
        }

        bucket->entries = new_entries;
        bucket->capacity = new_capacity;
    }

    // Add new entry at the end
    bucket->entries[bucket->count].key_value_data = key_value_data;
    bucket->count++;
    map->entry_count++;
    key_value_data = NULL;

Exit:
    ExReleaseSpinLockExclusive(&bucket->lock, old_irql);

    if (key_value_data != NULL) {
        client_dispatch_table->epoch_free(key_value_data);
    }

    return result;
}