// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"

// Buckets contain an array of pointers to value and keys.
// Buckets are immutable once inserted in to the hash-table and replaced when
// modified.

// Layout is:
// ebpf_hash_table_t.buckets->ebpf_hash_bucket_header_t.entries->data
// Keys are stored contiguously in ebpf_hash_bucket_header_t for fast
// searching, data is stored separately to prevent read-copy-update semantics
// from causing loss of updates.

typedef struct _ebpf_hash_bucket_entry
{
    uint8_t* data;
    uint8_t key[1];
} ebpf_hash_bucket_entry_t;

typedef struct _ebpf_hash_bucket_header
{
    size_t count;
    _Field_size_(count) ebpf_hash_bucket_entry_t entries[1];
} ebpf_hash_bucket_header_t;

struct _ebpf_hash_table
{
    uint32_t bucket_count;
    volatile int32_t entry_count;
    uint32_t seed;
    size_t key_size;
    size_t value_size;
    void* (*allocate)(size_t size);
    void (*free)(void* memory);
    void (*extract)(_In_ const uint8_t* value, _Outptr_ const uint8_t** data, _Out_ size_t* num);
    _Field_size_(bucket_count) ebpf_hash_bucket_header_t* volatile buckets[1];
};

typedef enum _ebpf_hash_bucket_operation
{
    EBPF_HASH_BUCKET_OPERATION_INSERT_OR_UPDATE,
    EBPF_HASH_BUCKET_OPERATION_INSERT,
    EBPF_HASH_BUCKET_OPERATION_UPDATE,
    EBPF_HASH_BUCKET_OPERATION_DELETE,
} ebpf_hash_bucket_operation_t;

/**
 * @brief Perform a rotate left on a value.
 *
 * @param[in] value Value to be rotated.
 * @param[in] count Count of bits to rotate.
 * @return Rotated value.
 */
static inline unsigned long
_ebpf_rol(uint32_t value, size_t count)
{
    return (value << count) | (value >> (32 - count));
}

// Ported from https://github.com/aappleby/smhasher
// Quote from https://github.com/aappleby/smhasher/blob/61a0530f28277f2e850bfc39600ce61d02b518de/src/MurmurHash3.cpp#L2
// "MurmurHash3 was written by Austin Appleby, and is placed in the public domain."

/**
 * @brief An implementation of the murmur3_32 hash function. This is a high
 * performance non-cryptographic hash function.
 *
 * @param[in] key Pointer to key to hash.
 * @param[in] length Length of key to hash.
 * @param[in] seed Seed to randomize hash.
 * @return Hash of key.
 */
unsigned long
_ebpf_murmur3_32(_In_ const uint8_t* key, size_t length, uint32_t seed)
{
    uint32_t c1 = 0xcc9e2d51;
    uint32_t c2 = 0x1b873593;
    uint32_t r1 = 15;
    uint32_t r2 = 13;
    uint32_t m = 5;
    uint32_t n = 0xe6546b64;
    uint32_t hash = seed;

    for (size_t index = 0; (length - index) > 3; index += 4) {
        uint32_t k = *(uint32_t*)(key + index);
        k *= c1;
        k = _ebpf_rol(k, r1);
        k *= c2;

        hash ^= k;
        hash = _ebpf_rol(hash, r2);
        hash *= m;
        hash += n;
    }
    unsigned long remainder = 0;
    for (size_t index = length & (~3); index < length; index++) {
        remainder <<= 8;
        remainder |= key[index];
    }
    remainder *= c1;
    remainder = _ebpf_rol(remainder, r1);
    remainder *= c2;

    hash ^= remainder;
    hash ^= (uint32_t)length;
    hash *= 0x85ebca6b;
    hash ^= (hash >> r2);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);
    return hash;
}

/**
 * @brief Given two potentially non-comparable key values, extract the key and
 * compare them.
 *
 * @param[in] hash_table Hash table the keys belong to.
 * @param[in] key_a First key.
 * @param[in] key_b Second key.
 * @retval -1 if key_a < key_b
 * @retval 0 if key_a == key_b
 * @retval 1 if key_a > key_b
 */
static int
_ebpf_hash_table_compare(_In_ const ebpf_hash_table_t* hash_table, _In_ const uint8_t* key_a, _In_ const uint8_t* key_b)
{
    size_t length_a;
    size_t length_b;
    const uint8_t* data_a;
    const uint8_t* data_b;
    if (hash_table->extract) {
        hash_table->extract(key_a, &data_a, &length_a);
        hash_table->extract(key_b, &data_b, &length_b);
    } else {
        length_a = hash_table->key_size;
        data_a = key_a;
        length_b = hash_table->key_size;
        data_b = key_b;
    }
    if (length_a < length_b) {
        return -1;
    }
    if (length_a > length_b) {
        return 1;
    }
    return memcmp(data_a, data_b, length_a);
}

/**
 * @brief Given a potentially non-comparable key value, extract the key and
 * compute the hash.
 *
 * @param[in] hash_table Hash table the keys belong to.
 * @param[in] key Key to hash.
 * @return Hash of key.
 */
static uint32_t
_ebpf_hash_table_compute_hash(_In_ const ebpf_hash_table_t* hash_table, _In_ const uint8_t* key)
{
    size_t length;
    const uint8_t* data;
    if (hash_table->extract) {
        hash_table->extract(key, &data, &length);
    } else {
        length = hash_table->key_size;
        data = key;
    }
    return _ebpf_murmur3_32(data, length, hash_table->seed);
}

/**
 * @brief Given a pointer to a bucket, compute the offset of a bucket entry.
 *
 * @param [in] key_size Size of key.
 * @param [in] bucket Pointer to start of the bucket.
 * @param [in] index Index into the bucket.
 * @return Pointer to the ebpf_hash_bucket_entry_t.
 */
ebpf_hash_bucket_entry_t*
_ebpf_hash_table_bucket_entry(size_t key_size, _In_ ebpf_hash_bucket_header_t* bucket, size_t index)
{
    uint8_t* offset = (uint8_t*)bucket->entries;
    size_t entry_size = EBPF_OFFSET_OF(ebpf_hash_bucket_entry_t, key) + key_size;

    return (ebpf_hash_bucket_entry_t*)(offset + (size_t)index * entry_size);
}

/**
 * @brief Perform an atomic replacement of a bucket in the hash table.
 * Operations include insert and delete of elements.
 *
 * @param[in] hash_table Hash table to update.
 * @param[in] key Key to operate on.
 * @param[in] value Value to be inserted or NULL.
 * @param[in] operation Operation to perform.
 * @retval EBPF_SUCCESS The operation succeeded.
 * @retval EBPF_KEY_NOT_FOUND The specified key is not present in the bucket.
 * @retval EBPF_NO_MEMORY Insufficient memory to construct new bucket or value.
 */
static ebpf_result_t
_ebpf_hash_table_replace_bucket(
    _In_ ebpf_hash_table_t* hash_table,
    _In_ const uint8_t* key,
    _In_opt_ const uint8_t* value,
    ebpf_hash_bucket_operation_t operation)
{
    ebpf_result_t result;
    size_t index;
    size_t old_data_index = MAXSIZE_T;
    size_t entry_size = EBPF_OFFSET_OF(ebpf_hash_bucket_entry_t, key) + hash_table->key_size;
    uint8_t* old_data = NULL;
    uint8_t* new_data = NULL;
    uint8_t* delete_data = NULL;
    uint32_t hash;
    ebpf_hash_bucket_header_t* old_bucket = NULL;
    ebpf_hash_bucket_header_t* new_bucket = NULL;
    ebpf_hash_bucket_header_t* delete_bucket = NULL;
    hash = _ebpf_hash_table_compute_hash(hash_table, key);

    switch (operation) {
    case EBPF_HASH_BUCKET_OPERATION_INSERT_OR_UPDATE:
    case EBPF_HASH_BUCKET_OPERATION_INSERT:
    case EBPF_HASH_BUCKET_OPERATION_UPDATE:
        new_data = hash_table->allocate(hash_table->value_size);
        if (!new_data) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }
        delete_data = new_data;
        if (value) {
            memcpy(new_data, value, hash_table->value_size);
        }
        break;
    case EBPF_HASH_BUCKET_OPERATION_DELETE:
        break;
    }

    for (;;) {
        size_t old_bucket_count = 0;
        size_t new_bucket_count = 0;

        new_bucket = NULL;
        old_data = NULL;
        delete_bucket = new_bucket;
        delete_data = new_data;

        // Capture current bucket pointer.
        old_bucket = hash_table->buckets[hash % hash_table->bucket_count];

        // If the old_bucket exists, capture its count.
        if (old_bucket) {
            old_bucket_count = old_bucket->count;
        }

        // Find the old key index if it exists.
        if (old_bucket) {
            for (index = 0; index < old_bucket_count; index++) {
                ebpf_hash_bucket_entry_t* entry =
                    _ebpf_hash_table_bucket_entry(hash_table->key_size, old_bucket, index);
                ebpf_assert(entry);
                if (_ebpf_hash_table_compare(hash_table, key, entry->key) == 0) {
                    // If old_data exists, remove it.
                    old_data = entry->data;
                    old_data_index = index;
                    break;
                }
            }
        }

        // new_bucket_count is either old_bucket_count +1 or -1.
        new_bucket_count = old_bucket_count;

        switch (operation) {
        // Fail if the key is not found and this is a update or delete.
        case EBPF_HASH_BUCKET_OPERATION_UPDATE:
            if (old_data_index == MAXSIZE_T) {
                result = EBPF_KEY_NOT_FOUND;
                goto Done;
            }
            break;
        case EBPF_HASH_BUCKET_OPERATION_DELETE:
            if (old_data_index == MAXSIZE_T) {
                result = EBPF_KEY_NOT_FOUND;
                goto Done;
            } else {
                new_bucket_count--;
            }
            break;
        // Permit it if this is an insert or insert_or_update.
        case EBPF_HASH_BUCKET_OPERATION_INSERT:
            if (old_data_index != MAXSIZE_T) {
                result = EBPF_OBJECT_ALREADY_EXISTS;
                goto Done;
            } else {
                new_bucket_count++;
            }
            break;
        case EBPF_HASH_BUCKET_OPERATION_INSERT_OR_UPDATE:
            if (old_data_index == MAXSIZE_T) {
                new_bucket_count++;
            }
            break;
        }

        ebpf_assert(new_bucket_count < MAXUINT32);

        if (new_bucket_count) {
            new_bucket = hash_table->allocate(entry_size * new_bucket_count + sizeof(ebpf_hash_bucket_header_t));
            if (!new_bucket) {
                result = EBPF_NO_MEMORY;
                goto Done;
            }
            delete_bucket = new_bucket;

            // Copy everything except old entry over.
            for (index = 0; index < old_bucket_count; index++) {
                ebpf_hash_bucket_entry_t* old_entry =
                    _ebpf_hash_table_bucket_entry(hash_table->key_size, old_bucket, index);
                ebpf_hash_bucket_entry_t* new_entry =
                    _ebpf_hash_table_bucket_entry(hash_table->key_size, new_bucket, new_bucket->count);

                if (index == old_data_index) {
                    continue;
                }
                memcpy(new_entry, old_entry, entry_size);
                new_bucket->count++;
            }

            // If new_data exists, add it to the end.
            if (new_data) {
                ebpf_assert(new_bucket_count > new_bucket->count);
                ebpf_hash_bucket_entry_t* new_entry =
                    _ebpf_hash_table_bucket_entry(hash_table->key_size, new_bucket, new_bucket->count);
                new_entry->data = new_data;
                memcpy(new_entry->key, key, hash_table->key_size);
                new_bucket->count++;
            }
        }

        ebpf_assert(
            (new_bucket == NULL && new_bucket_count == 0) || // No new bucket.
            (new_bucket_count == new_bucket->count));        // New bucket is full.

        if (ebpf_interlocked_compare_exchange_pointer(
                (void* volatile*)&hash_table->buckets[hash % hash_table->bucket_count], new_bucket, old_bucket) ==
            old_bucket) {
            delete_bucket = old_bucket;
            delete_data = old_data;
            break;
        } else {
            // Delete new_bucket and try again.
            hash_table->free(new_bucket);
        }
    }

    switch (operation) {
    case EBPF_HASH_BUCKET_OPERATION_INSERT:
        ebpf_interlocked_increment_int32(&hash_table->entry_count);
        break;
    case EBPF_HASH_BUCKET_OPERATION_INSERT_OR_UPDATE:
        if (!old_data)
            ebpf_interlocked_increment_int32(&hash_table->entry_count);
        break;
    case EBPF_HASH_BUCKET_OPERATION_UPDATE:
        break;
    case EBPF_HASH_BUCKET_OPERATION_DELETE:
        ebpf_interlocked_decrement_int32(&hash_table->entry_count);
        break;
    }

    result = EBPF_SUCCESS;

Done:
    hash_table->free(delete_bucket);
    hash_table->free(delete_data);
    return result;
}

ebpf_result_t
ebpf_hash_table_create(
    _Out_ ebpf_hash_table_t** hash_table,
    _In_ void* (*allocate)(size_t size),
    _In_ void (*free)(void* memory),
    size_t key_size,
    size_t value_size,
    size_t bucket_count,
    _In_opt_ void (*extract)(_In_ const uint8_t* value, _Outptr_ const uint8_t** data, _Out_ size_t* num))
{
    ebpf_result_t retval;
    ebpf_hash_table_t* table = NULL;
    size_t table_size = 0;
    retval = ebpf_safe_size_t_multiply(sizeof(ebpf_hash_bucket_header_t*), bucket_count, &table_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }
    retval = ebpf_safe_size_t_add(table_size, EBPF_OFFSET_OF(ebpf_hash_table_t, buckets), &table_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    table = allocate(table_size);
    if (table == NULL) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    table->key_size = key_size;
    table->value_size = value_size;
    table->allocate = allocate;
    table->free = free;
    table->bucket_count = (uint32_t)bucket_count;
    table->entry_count = 0;
    table->seed = ebpf_random_uint32();
    table->extract = extract;

    *hash_table = table;
    retval = EBPF_SUCCESS;
Done:
    return retval;
}

void
ebpf_hash_table_destroy(_In_opt_ _Post_ptr_invalid_ ebpf_hash_table_t* hash_table)
{
    size_t index;
    if (!hash_table) {
        return;
    }

    for (index = 0; index < hash_table->bucket_count; index++) {
        ebpf_hash_bucket_header_t* bucket = (ebpf_hash_bucket_header_t*)hash_table->buckets[index];
        if (bucket) {
            size_t inner_index;
            for (inner_index = 0; inner_index < bucket->count; inner_index++) {
                ebpf_hash_bucket_entry_t* entry =
                    _ebpf_hash_table_bucket_entry(hash_table->key_size, bucket, inner_index);
                hash_table->free(entry->data);
            }
            hash_table->free(bucket);
            hash_table->buckets[index] = NULL;
        }
    }
    hash_table->free(hash_table);
}

ebpf_result_t
ebpf_hash_table_find(_In_ ebpf_hash_table_t* hash_table, _In_ const uint8_t* key, _Outptr_ uint8_t** value)
{
    ebpf_result_t retval;
    uint32_t hash;
    uint8_t* data = NULL;
    size_t index;
    ebpf_hash_bucket_header_t* bucket;

    if (!hash_table || !key) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    hash = _ebpf_hash_table_compute_hash(hash_table, key);
    bucket = hash_table->buckets[hash % hash_table->bucket_count];
    if (!bucket) {
        retval = EBPF_KEY_NOT_FOUND;
        goto Done;
    }

    for (index = 0; index < bucket->count; index++) {
        ebpf_hash_bucket_entry_t* entry = _ebpf_hash_table_bucket_entry(hash_table->key_size, bucket, index);
        if (_ebpf_hash_table_compare(hash_table, key, entry->key) == 0) {
            data = entry->data;
            break;
        }
    }

    if (!data) {
        retval = EBPF_KEY_NOT_FOUND;
        goto Done;
    }

    *value = data;
    retval = EBPF_SUCCESS;
Done:
    return retval;
}

ebpf_result_t
ebpf_hash_table_update(
    _In_ ebpf_hash_table_t* hash_table,
    _In_ const uint8_t* key,
    _In_opt_ const uint8_t* value,
    ebpf_hash_table_operations_t operation)
{
    ebpf_result_t retval;
    ebpf_hash_bucket_operation_t bucket_operation;

    if (!hash_table || !key) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    switch (operation) {
    case EBPF_HASH_TABLE_OPERATION_ANY:
        bucket_operation = EBPF_HASH_BUCKET_OPERATION_INSERT_OR_UPDATE;
        break;
    case EBPF_HASH_TABLE_OPERATION_INSERT:
        bucket_operation = EBPF_HASH_BUCKET_OPERATION_INSERT;
        break;
    case EBPF_HASH_TABLE_OPERATION_REPLACE:
        bucket_operation = EBPF_HASH_BUCKET_OPERATION_UPDATE;
        break;
    default:
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    retval = _ebpf_hash_table_replace_bucket(hash_table, key, value, bucket_operation);
Done:
    return retval;
}

ebpf_result_t
ebpf_hash_table_delete(_In_ ebpf_hash_table_t* hash_table, _In_ const uint8_t* key)
{
    ebpf_result_t retval;

    if (!hash_table || !key) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    retval = _ebpf_hash_table_replace_bucket(hash_table, key, NULL, EBPF_HASH_BUCKET_OPERATION_DELETE);

Done:
    return retval;
}

ebpf_result_t
ebpf_hash_table_next_key_pointer_and_value(
    _In_ ebpf_hash_table_t* hash_table,
    _In_opt_ const uint8_t* previous_key,
    _Outptr_ uint8_t** next_key_pointer,
    _Outptr_opt_ uint8_t** value)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t hash;
    ebpf_hash_bucket_entry_t* next_entry = NULL;
    size_t bucket_index;
    size_t data_index;
    bool found_entry = false;

    if (!hash_table || !next_key_pointer) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    hash = (previous_key != NULL) ? _ebpf_hash_table_compute_hash(hash_table, previous_key) : 0;

    for (bucket_index = hash % hash_table->bucket_count; bucket_index < hash_table->bucket_count; bucket_index++) {
        ebpf_hash_bucket_header_t* bucket = hash_table->buckets[bucket_index];
        // Skip empty buckets.
        if (!bucket) {
            continue;
        }

        // Pick first entry if no previous key.
        if (!previous_key) {
            next_entry = _ebpf_hash_table_bucket_entry(hash_table->key_size, bucket, 0);
            break;
        }

        for (data_index = 0; data_index < bucket->count; data_index++) {
            ebpf_hash_bucket_entry_t* entry = _ebpf_hash_table_bucket_entry(hash_table->key_size, bucket, data_index);
            if (!entry) {
                result = EBPF_INVALID_ARGUMENT;
                goto Done;
            }
            // Do we have the previous key?
            if (found_entry) {
                // Yes, then this is the next key.
                next_entry = entry;
                break;
            }

            // Is this the previous key?
            if (_ebpf_hash_table_compare(hash_table, previous_key, entry->key) == 0) {
                // Yes, record its location.
                found_entry = true;
            }
        }
        if (next_entry) {
            break;
        }
    }
    if (!next_entry) {
        result = EBPF_NO_MORE_KEYS;
        goto Done;
    }

    result = EBPF_SUCCESS;

    if (value)
        *value = next_entry->data;

    *next_key_pointer = next_entry->key;

Done:

    return result;
}

ebpf_result_t
ebpf_hash_table_next_key_and_value(
    _In_ ebpf_hash_table_t* hash_table,
    _In_opt_ const uint8_t* previous_key,
    _Out_ uint8_t* next_key,
    _Inout_opt_ uint8_t** next_value)
{
    uint8_t* next_key_pointer;
    ebpf_result_t result =
        ebpf_hash_table_next_key_pointer_and_value(hash_table, previous_key, &next_key_pointer, next_value);
    if (result == EBPF_SUCCESS) {
        memcpy(next_key, next_key_pointer, hash_table->key_size);
    }
    return result;
}

ebpf_result_t
ebpf_hash_table_next_key(
    _In_ ebpf_hash_table_t* hash_table, _In_opt_ const uint8_t* previous_key, _Out_ uint8_t* next_key)
{
    return ebpf_hash_table_next_key_and_value(hash_table, previous_key, next_key, NULL);
}

size_t
ebpf_hash_table_key_count(_In_ ebpf_hash_table_t* hash_table)
{
    return hash_table->entry_count;
}
