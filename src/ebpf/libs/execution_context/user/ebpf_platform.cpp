/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/
#include <stdint.h>
#include <stdbool.h>
#include <set>
#include <map>
#include <vector>
#include "protocol.h"
#include "ebpf_core.h"
#include "ebpf_platform.h"
#include <Windows.h>
#include <mutex>

std::set<uint64_t> _executable_segments;

void* ebpf_allocate(size_t size, ebpf_memory_type_t type)
{
    void* memory;
    if (type == EBPF_MEMORY_EXECUTE)
    {
        memory = VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (memory)
        {
            _executable_segments.insert({ reinterpret_cast<uint64_t>(memory) });
        }
        return memory;
    }
    else
    {
        return malloc(size);
    }
}

void ebpf_free(void* memory)
{
    if (_executable_segments.find(reinterpret_cast<uint64_t>(memory)) != _executable_segments.end())
    {
        VirtualFree(memory, 0, MEM_RELEASE);
    }
    else
    {
        free(memory);
    }
}

ebpf_error_code_t ebpf_safe_size_t_multiply(size_t multiplicand, size_t multiplier, size_t* result)
{
    *result = multiplicand * multiplier;
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t ebpf_safe_size_t_add(size_t augend, size_t addend, size_t* result)
{
    *result = augend + addend;
    return EBPF_ERROR_SUCCESS;
}

void ebpf_lock_create(ebpf_lock_t* lock)
{
    auto mutex = new std::mutex();
    *reinterpret_cast<std::mutex**>(lock) = mutex;
}

void ebpf_lock_destroy(ebpf_lock_t* lock)
{
    auto mutex = *reinterpret_cast<std::mutex**>(lock);
    delete mutex;
}

void ebpf_lock_lock(ebpf_lock_t* lock, ebpf_lock_state_t* state)
{
    auto mutex = *reinterpret_cast<std::mutex**>(lock);
    mutex->lock();
}

void ebpf_lock_unlock(ebpf_lock_t* lock, ebpf_lock_state_t* state)
{
    auto mutex = *reinterpret_cast<std::mutex**>(lock);
    mutex->unlock();
}

typedef struct _hash_table {
    size_t key_size;
    size_t value_size;
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> hash_table;
} hash_table_t;

ebpf_error_code_t ebpf_hash_table_create(ebpf_hash_table_t** hash_table, size_t key_size, size_t value_size)
{
    *hash_table = reinterpret_cast<ebpf_hash_table_t *>(new hash_table_t());
    return EBPF_ERROR_SUCCESS;
}

void ebpf_hash_table_destroy(ebpf_hash_table_t* hash_table)
{
    hash_table_t* local_hash_table = reinterpret_cast<decltype(local_hash_table)>(hash_table);

    delete local_hash_table;
}

ebpf_error_code_t ebpf_hash_table_lookup(ebpf_hash_table_t* hash_table, const uint8_t* key, uint8_t** value)
{
    hash_table_t* local_hash_table = reinterpret_cast<decltype(local_hash_table)>(hash_table);
    std::vector<uint8_t> local_key(key, key + local_hash_table->key_size);
    auto local_value = local_hash_table->hash_table.find(local_key);
    if (local_value == local_hash_table->hash_table.end())
    {
        return EBPF_ERROR_NOT_FOUND;
    }

    std::copy(local_value->second.begin(), local_value->second.end(), *value);
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t ebpf_hash_table_update(ebpf_hash_table_t* hash_table, const uint8_t* key, const uint8_t* value)
{
    hash_table_t* local_hash_table = reinterpret_cast<decltype(local_hash_table)>(hash_table);
    std::vector<uint8_t> local_key(key, key + local_hash_table->key_size);
    std::vector<uint8_t> local_value(value, value + local_hash_table->value_size);
    
    local_hash_table->hash_table[local_key] = local_value;
    return EBPF_ERROR_SUCCESS;

}

ebpf_error_code_t ebpf_hash_table_delete(ebpf_hash_table_t* hash_table, const uint8_t* key)
{
    hash_table_t* local_hash_table = reinterpret_cast<decltype(local_hash_table)>(hash_table);
    std::vector<uint8_t> local_key(key, key + local_hash_table->key_size);
    auto iter = local_hash_table->hash_table.find(local_key);
    if (iter == local_hash_table->hash_table.end())
    {
        return EBPF_ERROR_NOT_FOUND;
    }
    local_hash_table->hash_table.erase(iter);
    return EBPF_ERROR_SUCCESS;
}

