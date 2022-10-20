// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_state.h"
#include "ebpf_epoch.h"

#define EBPF_MAX_STATE_ENTRIES 64

// Table to track what state for each thread.
static ebpf_hash_table_t* _ebpf_state_thread_table = NULL;

static int64_t _ebpf_state_next_index;

// Table to track what state for each CPU.
typedef struct _ebpf_state_entry
{
    uintptr_t state[EBPF_MAX_STATE_ENTRIES];
} ebpf_state_entry_t;

static _Writable_elements_(_ebpf_state_cpu_table_size) ebpf_state_entry_t* _ebpf_state_cpu_table = NULL;
static uint32_t _ebpf_state_cpu_table_size = 0;

ebpf_result_t
ebpf_state_initiate()
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value = EBPF_SUCCESS;

    _ebpf_state_next_index = 0;

    if (ebpf_is_non_preemptible_work_item_supported()) {
        _ebpf_state_cpu_table_size = ebpf_get_cpu_count();
        _Analysis_assume_(_ebpf_state_cpu_table_size >= 1);

        _ebpf_state_cpu_table = ebpf_allocate_cache_aligned(sizeof(ebpf_state_entry_t) * _ebpf_state_cpu_table_size);
        if (!_ebpf_state_cpu_table) {
            return_value = EBPF_NO_MEMORY;
            goto Error;
        }
    }

    return_value = ebpf_hash_table_create(
        &_ebpf_state_thread_table,
        ebpf_epoch_allocate,
        ebpf_epoch_free,
        sizeof(uint64_t),
        sizeof(ebpf_state_entry_t),
        ebpf_get_cpu_count(),
        NULL);
    if (return_value != EBPF_SUCCESS) {
        goto Error;
    }

    EBPF_RETURN_RESULT(return_value);

Error:
    ebpf_state_terminate();
    EBPF_RETURN_RESULT(return_value);
}

/**
 * @brief Uninitialize the eBPF state tracking module.
 *
 */
void
ebpf_state_terminate()
{
    EBPF_LOG_ENTRY();
    ebpf_hash_table_destroy(_ebpf_state_thread_table);
    _ebpf_state_thread_table = NULL;
    ebpf_free_cache_aligned(_ebpf_state_cpu_table);
    _ebpf_state_cpu_table = NULL;
    EBPF_RETURN_VOID();
}

ebpf_result_t
ebpf_state_allocate_index(_Out_ size_t* new_index)
{
    EBPF_LOG_ENTRY();
    if (_ebpf_state_next_index >= EBPF_MAX_STATE_ENTRIES) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }

    *new_index = ebpf_interlocked_increment_int64(&_ebpf_state_next_index) - 1;
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

ebpf_result_t
_ebpf_state_get_entry(_Out_ ebpf_state_entry_t** entry)
{
    // High frequency call, don't log entry/exit.
    ebpf_state_entry_t* local_entry = NULL;

    if (!ebpf_is_non_preemptible_work_item_supported() || ebpf_is_preemptible()) {
        ebpf_result_t return_value;
        uint64_t current_thread_id = ebpf_get_current_thread_id();

        return_value =
            ebpf_hash_table_find(_ebpf_state_thread_table, (const uint8_t*)&current_thread_id, (uint8_t**)&local_entry);

        if (return_value == EBPF_KEY_NOT_FOUND) {
            ebpf_state_entry_t new_entry = {0};

            return_value = ebpf_hash_table_update(
                _ebpf_state_thread_table,
                (const uint8_t*)&current_thread_id,
                (const uint8_t*)&new_entry,
                EBPF_HASH_TABLE_OPERATION_INSERT);

            if (return_value != EBPF_SUCCESS) {
                return return_value;
            }

            return_value = ebpf_hash_table_find(
                _ebpf_state_thread_table, (const uint8_t*)&current_thread_id, (uint8_t**)&local_entry);
        }
    } else {
        uint32_t current_cpu = ebpf_get_current_cpu();
        if (current_cpu >= _ebpf_state_cpu_table_size) {
            return EBPF_OPERATION_NOT_SUPPORTED;
        }
        local_entry = _ebpf_state_cpu_table + current_cpu;
    }
    *entry = local_entry;
    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_state_store(size_t index, uintptr_t value)
{
    // High frequency call, don't log entry/exit.
    ebpf_state_entry_t* entry = NULL;
    ebpf_result_t return_value;

    return_value = _ebpf_state_get_entry(&entry);
    if (return_value == EBPF_SUCCESS) {
        entry->state[index] = value;
    }
    return return_value;
}

ebpf_result_t
ebpf_state_load(size_t index, _Out_ uintptr_t* value)
{
    // High frequency call, don't log entry/exit.
    ebpf_state_entry_t* entry = NULL;
    ebpf_result_t return_value;

    return_value = _ebpf_state_get_entry(&entry);
    if (return_value == EBPF_SUCCESS) {
        *value = entry->state[index];
    }
    return return_value;
}
