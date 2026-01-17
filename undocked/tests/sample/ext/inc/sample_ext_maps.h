// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

// Sample extension custom map implementations.
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

typedef struct _sample_hash_map_entry
{
    uint32_t value;
} sample_hash_map_entry_t;

// typedef struct _sample_base_array_map
// {
//     sample_core_map_t core;
//     uint8_t* data;
// } sample_base_array_map_t;

// static inline ebpf_result_t
// _sample_array_map_find_entry_common(
//     _In_ const sample_base_array_map_t* map,
//     size_t key_size,
//     _In_reads_(key_size) const uint8_t* key,
//     _Outptr_ uint8_t** value,
//     uint32_t flags)
// {
//     UNREFERENCED_PARAMETER(flags);

//     if (key == NULL || value == NULL) {
//         return EBPF_INVALID_ARGUMENT;
//     }
//     if (flags & EBPF_MAP_FIND_FLAG_DELETE) {
//         // Deletion is not supported for array map.
//         return EBPF_INVALID_ARGUMENT;
//     }

//     if (!(flags & EBPF_MAP_FLAG_HELPER) && key_size != map->core.key_size) {
//         return EBPF_INVALID_ARGUMENT;
//     }

//     // In an array map, the key is an index.
//     uint32_t index = *(uint32_t*)key;
//     if (index >= map->core.max_entries) {
//         return EBPF_OBJECT_NOT_FOUND;
//     }

//     *value = map->data + ((size_t)index * map->core.value_size);
//     return EBPF_SUCCESS;
// }

// static ebpf_result_t
// _sample_array_map_update_entry_common(
//     _In_ const sample_base_array_map_t* map,
//     size_t key_size,
//     _In_reads_(key_size) const uint8_t* key,
//     size_t value_size,
//     _In_reads_(value_size) const uint8_t* value,
//     ebpf_map_option_t option,
//     uint32_t flags)
// {
//     UNREFERENCED_PARAMETER(flags);
//     UNREFERENCED_PARAMETER(option);

//     if (key == NULL || value == NULL || option == EBPF_NOEXIST) {
//         return EBPF_INVALID_ARGUMENT;
//     }

//     if (!(flags & EBPF_MAP_FLAG_HELPER) && (key_size != map->core.key_size || value_size != map->core.value_size)) {
//         return EBPF_INVALID_ARGUMENT;
//     }

//     // In an array map, the key is an index.
//     uint32_t index = *(uint32_t*)key;
//     if (index >= map->core.max_entries) {
//         return EBPF_OBJECT_NOT_FOUND;
//     }

//     // Update existing entry
//     memcpy(map->data + ((size_t)index * map->core.value_size), value, map->core.value_size);
//     return EBPF_SUCCESS;
// }

// static ebpf_result_t
// _sample_array_map_delete_entry_common(
//     _In_ const sample_base_array_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, uint32_t
//     flags)
// {
//     UNREFERENCED_PARAMETER(flags);

//     if (map == NULL || key == NULL) {
//         return EBPF_INVALID_ARGUMENT;
//     }

//     if (!(flags & EBPF_MAP_FLAG_HELPER) && key_size != map->core.key_size) {
//         return EBPF_INVALID_ARGUMENT;
//     }

//     // In an array map, the key is an index.
//     uint32_t index = *(uint32_t*)key;
//     if (index >= map->core.max_entries) {
//         return EBPF_OBJECT_NOT_FOUND;
//     }
//     memset(map->data + ((size_t)index * map->core.value_size), 0, map->core.value_size);
//     return EBPF_SUCCESS;
// }

// static ebpf_result_t
// _sample_array_map_get_next_key_and_value_common(
//     _In_ const sample_base_array_map_t* map,
//     size_t key_size,
//     _In_opt_ const uint8_t* previous_key,
//     _Out_writes_(key_size) uint8_t* next_key,
//     _Outptr_opt_ uint8_t** next_value)
// {
//     ebpf_result_t result = EBPF_NO_MORE_KEYS;
//     if (map == NULL || next_key == NULL) {
//         return EBPF_INVALID_ARGUMENT;
//     }

//     if (key_size != map->core.key_size) {
//         return EBPF_INVALID_ARGUMENT;
//     }

//     if (previous_key != NULL) {
//         uint32_t prev_index = *(uint32_t*)previous_key;
//         if (prev_index + 1 < map->core.max_entries) {
//             uint32_t next_index = prev_index + 1;
//             memcpy(next_key, &next_index, map->core.key_size);
//             if (next_value != NULL) {
//                 *next_value = map->data + ((size_t)next_index * map->core.value_size);
//             }
//             result = EBPF_SUCCESS;
//         } else {
//             result = EBPF_NO_MORE_KEYS;
//         }
//     } else {
//         // Return first key if previous_key is NULL.
//         uint32_t first_index = 0;
//         memcpy(next_key, &first_index, map->core.key_size);
//         if (next_value != NULL) {
//             *next_value = map->data;
//         }
//         result = EBPF_SUCCESS;
//     }

//     return result;
// }

// // Hash bucket entry in array format
// typedef struct _sample_hash_bucket_entry
// {
//     uint8_t* key_value_data; // Key followed by value in contiguous memory
// } sample_hash_bucket_entry_t;

// typedef struct _sample_hash_bucket
// {
//     EX_SPIN_LOCK lock;                   // Reader-writer lock for this bucket
//     sample_hash_bucket_entry_t* entries; // Array of entries
//     uint32_t capacity;                   // Current capacity of entries array
//     uint32_t count;                      // Number of entries currently stored
// } sample_hash_bucket_t;

// typedef struct _sample_base_hash_map
// {
//     sample_core_map_t core;
//     uint32_t entry_count;
//     sample_hash_bucket_t* buckets; // Array of hash buckets
//     uint32_t bucket_count;
// } sample_base_hash_map_t;

// static uint32_t
// _sample_map_hash(const uint8_t* key, uint32_t key_size, uint32_t bucket_count)
// {
//     uint32_t hash = 0;
//     for (uint32_t i = 0; i < key_size; i++) {
//         hash = hash * 31 + key[i];
//     }
//     return hash % bucket_count;
// }

// static int32_t
// _sample_hash_map_find_entry_index_internal(sample_hash_bucket_t* bucket, const uint8_t* key, uint32_t key_size)
// {
//     // Assumes bucket is already locked (shared or exclusive)
//     for (uint32_t i = 0; i < bucket->count; i++) {
//         if (bucket->entries[i].key_value_data != NULL &&
//             memcmp(bucket->entries[i].key_value_data, key, key_size) == 0) {
//             return (int32_t)i;
//         }
//     }
//     return -1; // Not found
// }

// static ebpf_result_t
// _sample_hash_map_get_next_key_and_value_common(
//     _In_ sample_base_hash_map_t* map,
//     size_t key_size,
//     _In_ const uint8_t* previous_key,
//     _Out_writes_(key_size) uint8_t* next_key,
//     _Outptr_opt_ uint8_t** next_value)
// {
//     bool found_previous = (previous_key == NULL);
//     KIRQL old_irql;

//     UNREFERENCED_PARAMETER(key_size);

//     // Iterate through all buckets and their entries
//     for (uint32_t i = 0; i < map->bucket_count; i++) {
//         sample_hash_bucket_t* bucket = &map->buckets[i];

//         // Acquire shared lock for read access
//         old_irql = ExAcquireSpinLockShared(&bucket->lock);

//         for (uint32_t j = 0; j < bucket->count; j++) {
//             if (bucket->entries[j].key_value_data != NULL) {
//                 if (found_previous) {
//                     // Return the first entry after previous_key
//                     memcpy(next_key, bucket->entries[j].key_value_data, map->core.key_size);
//                     if (next_value != NULL) {
//                         *next_value = bucket->entries[j].key_value_data + map->core.key_size;
//                     }
//                     ExReleaseSpinLockShared(&bucket->lock, old_irql);
//                     return EBPF_SUCCESS;
//                 }
//                 if (previous_key != NULL &&
//                     memcmp(bucket->entries[j].key_value_data, previous_key, map->core.key_size) == 0) {
//                     found_previous = true;
//                 }
//             }
//         }

//         ExReleaseSpinLockShared(&bucket->lock, old_irql);
//     }

//     return EBPF_NO_MORE_KEYS;
// }

static ebpf_result_t
_sample_object_hash_map_delete_entry_common(
    ebpf_map_client_dispatch_table_t* client_dispatch_table,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    uint32_t flags)
{
    if (flags & EBPF_MAP_FLAG_HELPER) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    UNREFERENCED_PARAMETER(value_size);

    // The value is a pointer to an object. Read the pointer.
    sample_hash_map_entry_t* entry = (sample_hash_map_entry_t*)ReadULong64NoFence((volatile const uint64_t*)value);

    if (entry == NULL) {
        return EBPF_KEY_NOT_FOUND;
    }

    // Free the object.
    client_dispatch_table->epoch_free(entry);

    return EBPF_SUCCESS;
}

static ebpf_result_t
_sample_object_hash_map_find_entry_common(
    size_t in_value_size,
    _In_reads_(in_value_size) const uint8_t* in_value,
    size_t out_value_size,
    _Out_writes_opt_(out_value_size) uint8_t* out_value)
{
    UNREFERENCED_PARAMETER(in_value_size);
    UNREFERENCED_PARAMETER(out_value_size);

    // out_value cannot be NULL for object map.
    if (out_value == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    // The in_value is a pointer to an object. Read the pointer.
    sample_hash_map_entry_t* value = (sample_hash_map_entry_t*)ReadULong64NoFence((volatile const uint64_t*)in_value);

    if (value == NULL) {
        return EBPF_KEY_NOT_FOUND;
    }

    // Copy the value from the object to out_value.
    memcpy(out_value, &value->value, sizeof(uint32_t));

    return EBPF_SUCCESS;
}

static ebpf_result_t
_sample_object_hash_map_update_entry_common(
    ebpf_map_client_dispatch_table_t* client_dispatch_table,
    size_t in_value_size,
    _In_reads_(in_value_size) const uint8_t* in_value,
    size_t out_value_size,
    _Out_writes_opt_(out_value_size) uint8_t* out_value)
{
    UNREFERENCED_PARAMETER(in_value_size);
    UNREFERENCED_PARAMETER(out_value_size);

    // out_value cannot be NULL for object map.
    if (out_value == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Create a new object to hold the value.
    sample_hash_map_entry_t* value = (sample_hash_map_entry_t*)client_dispatch_table->epoch_allocate_with_tag(
        sizeof(sample_hash_map_entry_t), map_pool_tag);
    if (value == NULL) {
        return EBPF_NO_MEMORY;
    }

    // Copy the value from in_value to the object.
    memcpy(&value->value, in_value, sizeof(uint32_t));

    // Store the pointer to the object as a uint64_t.
    WriteULong64NoFence((volatile uint64_t*)out_value, (uint64_t)value);

    return EBPF_SUCCESS;
}
