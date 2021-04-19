/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#include "ebpf_platform.h"

typedef struct _ebpf_pinning_table
{
    ebpf_hash_table_t* hash_table;
    ebpf_lock_t lock;
    void (*acquire_reference)(void*);
    void (*release_reference)(void*);
} ebpf_pinning_table_t;

typedef struct _ebpf_pinning_entry
{
    void* object;
    uint8_t name[1];
} ebpf_pinning_entry_t;

static ebpf_hash_table_compare_result_t
_ebpf_pining_table_compare_function(const uint8_t* key1, const uint8_t* key2)
{
    const char* first_key = *(const char**)key1;
    const char* second_key = *(const char**)key2;

    int compare_result = _stricmp(first_key, second_key);
    if (compare_result < 0)
        return EBPF_HASH_TABLE_LESS_THAN;
    else if (compare_result > 0)
        return EBPF_HASH_TABLE_GREATER_THAN;
    else
        return EBPF_HASH_TABLE_EQUAL;
}

ebpf_error_code_t
ebpf_pinning_table_allocate(
    ebpf_pinning_table_t** pinning_table, void (*acquire_reference)(void*), void (*release_reference)(void*))
{
    ebpf_error_code_t return_value;
    *pinning_table = ebpf_allocate(sizeof(ebpf_pinning_table_t), EBPF_MEMORY_NO_EXECUTE);
    if (*pinning_table == NULL) {
        return_value = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }

    memset(*pinning_table, 0, sizeof(ebpf_pinning_table_t));

    ebpf_lock_create(&(*pinning_table)->lock);

    return_value = ebpf_hash_table_create(
        &(*pinning_table)->hash_table, ebpf_allocate, ebpf_free, sizeof(uint64_t), sizeof(uint64_t), _ebpf_pining_table_compare_function);

    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    (*pinning_table)->acquire_reference = acquire_reference;
    (*pinning_table)->release_reference = release_reference;

    return_value = EBPF_ERROR_SUCCESS;
Done:
    if (return_value != EBPF_ERROR_SUCCESS) {
        if ((*pinning_table))
            ebpf_hash_table_destroy((*pinning_table)->hash_table);

        ebpf_free(*pinning_table);
    }

    return return_value;
}

void
ebpf_pinning_table_free(ebpf_pinning_table_t* pinning_table)
{
    ebpf_error_code_t return_value;
    uint64_t key = 0;

    for (;;) {
        return_value = ebpf_hash_table_next_key(pinning_table->hash_table, NULL, (uint8_t*)&key);
        if (return_value != EBPF_ERROR_SUCCESS) {
            break;
        }
        ebpf_pinning_table_delete(pinning_table, (uint8_t*)key);
    }

    ebpf_hash_table_destroy(pinning_table->hash_table);
    ebpf_free(pinning_table);
}

ebpf_error_code_t
ebpf_pinning_table_insert(ebpf_pinning_table_t* pinning_table, const uint8_t* name, void* object)
{
    ebpf_lock_state_t state;
    ebpf_error_code_t return_value;
    uint64_t key;
    uint64_t value;
    ebpf_pinning_entry_t* entry = NULL;
    size_t name_length = strlen((const char*)name);
    entry = ebpf_allocate(sizeof(ebpf_pinning_entry_t) + name_length, EBPF_MEMORY_NO_EXECUTE);
    if (entry == NULL) {
        return_value = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }
    memset(entry, 0, sizeof(ebpf_pinning_entry_t) + name_length);
    entry->object = object;
    memcpy(entry->name, name, name_length);

    key = (uint64_t) & (entry->name);
    value = (uint64_t)entry;

    ebpf_lock_lock(&pinning_table->lock, &state);

    return_value = ebpf_hash_table_lookup(pinning_table->hash_table, (const uint8_t*)&key, (uint8_t**)&value);
    if (return_value == EBPF_ERROR_SUCCESS) {
        return_value = EBPF_ERROR_DUPLICATE_NAME;
    } else {
        return_value = ebpf_hash_table_update(pinning_table->hash_table, (const uint8_t*)&key, (const uint8_t*)&value);
        entry = NULL;
    }

    ebpf_lock_unlock(&pinning_table->lock, &state);

    if (return_value == EBPF_ERROR_SUCCESS) {
        pinning_table->acquire_reference(object);
    }

Done:
    ebpf_free(entry);

    return return_value;
}

ebpf_error_code_t
ebpf_pinning_table_lookup(ebpf_pinning_table_t* pinning_table, const uint8_t* name, void** object)
{
    ebpf_lock_state_t state;
    ebpf_error_code_t return_value;
    uint64_t key = (uint64_t)name;
    uint64_t* value = NULL;
    ebpf_pinning_entry_t* entry = NULL;

    ebpf_lock_lock(&pinning_table->lock, &state);
    return_value = ebpf_hash_table_lookup(pinning_table->hash_table, (const uint8_t*)&key, (uint8_t**)&value);

    if (return_value == EBPF_ERROR_SUCCESS) {
        entry = ((ebpf_pinning_entry_t*)*value);
        *object = entry->object;
        pinning_table->acquire_reference(*object);
    }

    ebpf_lock_unlock(&pinning_table->lock, &state);

    return return_value;
}

ebpf_error_code_t
ebpf_pinning_table_delete(ebpf_pinning_table_t* pinning_table, const uint8_t* name)
{
    ebpf_lock_state_t state;
    ebpf_error_code_t return_value;
    uint64_t key = (uint64_t)name;
    uint64_t* value = 0;
    ebpf_pinning_entry_t* entry = NULL;

    ebpf_lock_lock(&pinning_table->lock, &state);
    return_value = ebpf_hash_table_lookup(pinning_table->hash_table, (const uint8_t*)&key, (uint8_t**)&value);
    if (return_value == EBPF_ERROR_SUCCESS) {
        entry = ((ebpf_pinning_entry_t*)*value);
        return_value = ebpf_hash_table_delete(pinning_table->hash_table, (const uint8_t*)&key);
        if (return_value == EBPF_ERROR_SUCCESS) {
            pinning_table->release_reference(entry->object);
            ebpf_free(entry);
        }
    }
    ebpf_lock_unlock(&pinning_table->lock, &state);

    return return_value;
}