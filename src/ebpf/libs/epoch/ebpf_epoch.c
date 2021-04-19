/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#include "ebpf_epoch.h"

// Brief summary of how epoch tracking works.
// Each free operation increments the epoch and the freed memory is stamped with
// that epoch.
//
// Each block of code that accesses epoch freed memory wraps access in calls to
// ebpf_epoch_enter/ebpf_epoch_exit.
//
// Epoch tracking is handled differently for pre-emptable vs non-pre-emptable
// invocations.
//
// Non-pre-emptable invocations:
// 1) Tracked by the CPU they are running on as they don't switch CPUs.
// 2) Accessed without synchronization.
// 3) Set to the current epoch on entry.
//
// Pre-emptable invocations are:
// 1) Tracked by thread ID.
// 2) Accessed under a lock.
// 3) Set to the current epoch on entry.
// 4) Set to epoch 0 on exit.
//
// Memory can be freed only if there is no code using that epoch.
// The CPU epoch table and thread table are scanned to find the lowest epoch in use.
// The release epoch is then lowest epoch - 1 (if not 0).
//
// Note:
// CPU table entries aren't cleared on exit as we can't rely on
// memory ordering.
// i.e., thread doing the cleanup may have a stale view of the CPU table.
// As long as the entries in the CPU table increase, this gives correct behavior.
//

static ebpf_lock_t _ebpf_epoch_thread_table_lock = {0};

// Table to track what epoch each thread is on.
static ebpf_hash_table_t* _ebpf_epoch_thread_table = NULL;

// Table to track what epoch each CPU is on.
typedef struct _ebpf_epoch_cpu_entry
{
    int64_t epoch;
    epbf_non_preemtable_work_item_t* non_preemtable_work_item;
} ebpf_epoch_cpu_entry_t;

static ebpf_epoch_cpu_entry_t* _ebpf_epoch_cpu_table = NULL;
static uint32_t _ebpf_epoch_cpu_table_size = 0;

static volatile int64_t _ebpf_current_epoch = 1;

typedef struct _ebpf_epoch_allocation_header
{
    struct _ebpf_epoch_allocation_header* next;
    int64_t freed_epoch;
} ebpf_epoch_allocation_header_t;

static ebpf_lock_t _ebpf_epoch_free_list_lock = {0};
static ebpf_epoch_allocation_header_t _ebpf_epoch_free_list = {0};

// Release memory that was freed during this epoch or a prior epoch.
static void
ebpf_epoch_release_free_list(int64_t released_epoch);

// Get the highest epoch that is no longer in use.
static ebpf_error_code_t
ebpf_epoch_get_release_epoch(int64_t* released_epoch);

static void
_ebpf_epoch_update_cpu_entry(void* context, void* parameter_1);

ebpf_error_code_t
ebpf_epoch_initialize()
{
    ebpf_error_code_t return_value;
    uint32_t cpu_id;

    _ebpf_current_epoch = 1;

    return_value = ebpf_get_cpu_count(&_ebpf_epoch_cpu_table_size);
    if (return_value != EBPF_ERROR_SUCCESS) {
        goto Error;
    }

    ebpf_lock_create(&_ebpf_epoch_thread_table_lock);
    ebpf_lock_create(&_ebpf_epoch_free_list_lock);

    _ebpf_epoch_cpu_table =
        ebpf_allocate(_ebpf_epoch_cpu_table_size * sizeof(ebpf_epoch_cpu_entry_t), EBPF_MEMORY_NO_EXECUTE);
    if (!_ebpf_epoch_cpu_table) {
        return_value = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Error;
    }

    memset(_ebpf_epoch_cpu_table, 0, _ebpf_epoch_cpu_table_size * sizeof(ebpf_epoch_cpu_entry_t));

    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_table_size; cpu_id++) {
        _ebpf_epoch_cpu_table[cpu_id].epoch = 0;
        return_value = ebpf_allocate_non_preemptable_work_item(
            &_ebpf_epoch_cpu_table[cpu_id].non_preemtable_work_item,
            cpu_id,
            _ebpf_epoch_update_cpu_entry,
            &_ebpf_epoch_cpu_table[cpu_id]);

        // Ignore if not supported.
        if (return_value == EBPF_ERROR_NOT_SUPPORTED)
            return_value = EBPF_ERROR_SUCCESS;

        if (return_value != EBPF_ERROR_SUCCESS)
            break;
    }

    if (return_value != EBPF_ERROR_SUCCESS) {
        for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_table_size; cpu_id++) {
            ebpf_free_non_preemptable_work_item(_ebpf_epoch_cpu_table[cpu_id].non_preemtable_work_item);
        }
    }

    return_value =
        ebpf_hash_table_create(&_ebpf_epoch_thread_table, ebpf_allocate, ebpf_free, sizeof(uint64_t), sizeof(int64_t));
    if (return_value != EBPF_ERROR_SUCCESS) {
        goto Error;
    }

    return return_value;

Error:
    ebpf_epoch_terminate();
    return return_value;
}

void
ebpf_epoch_terminate()
{
    ebpf_hash_table_destroy(_ebpf_epoch_thread_table);
    ebpf_free(_ebpf_epoch_cpu_table);
    ebpf_lock_destroy(&_ebpf_epoch_thread_table_lock);
    ebpf_epoch_release_free_list(INT64_MAX);
    ebpf_lock_destroy(&_ebpf_epoch_free_list_lock);
}

ebpf_error_code_t
ebpf_epoch_enter()
{
    if (ebpf_is_preemptable()) {
        ebpf_error_code_t return_value;
        ebpf_lock_state_t lock_state;
        uint64_t current_thread_id = ebpf_get_current_thread_id();
        int64_t current_epoch = _ebpf_current_epoch;
        ebpf_lock_lock(&_ebpf_epoch_thread_table_lock, &lock_state);
        return_value = ebpf_hash_table_update(
            _ebpf_epoch_thread_table, (const uint8_t*)&current_thread_id, (const uint8_t*)&current_epoch);
        ebpf_lock_unlock(&_ebpf_epoch_thread_table_lock, &lock_state);
        return return_value;
    } else {
        uint32_t current_cpu = ebpf_get_current_cpu();
        if (current_cpu > _ebpf_epoch_cpu_table_size) {
            return EBPF_ERROR_NOT_SUPPORTED;
        }

        _ebpf_epoch_cpu_table[current_cpu].epoch = _ebpf_current_epoch;
        return EBPF_ERROR_SUCCESS;
    }
}

void
ebpf_epoch_exit()
{
    if (ebpf_is_preemptable()) {
        ebpf_lock_state_t lock_state;
        uint64_t current_thread_id = ebpf_get_current_thread_id();
        int64_t current_epoch = 0;
        ebpf_lock_lock(&_ebpf_epoch_thread_table_lock, &lock_state);
        ebpf_hash_table_update(
            _ebpf_epoch_thread_table, (const uint8_t*)&current_thread_id, (const uint8_t*)&current_epoch);
        ebpf_lock_unlock(&_ebpf_epoch_thread_table_lock, &lock_state);
    } else {
        uint32_t current_cpu = ebpf_get_current_cpu();
        if (current_cpu > _ebpf_epoch_cpu_table_size) {
            return;
        }

        _ebpf_epoch_cpu_table[current_cpu].epoch = _ebpf_current_epoch;
    }

    // TODO: Investigate if this causes performance issues.
    if (_ebpf_epoch_free_list.next != NULL) {
        ebpf_epoch_flush();
    }
}

void
ebpf_epoch_flush()
{
    ebpf_error_code_t return_value;
    int64_t released_epoch;
    uint32_t cpu_id;

    // Schedule a non-preemptable work item to bring the CPU up to the current
    // epoch.
    // Note: May not affect the current flush.
    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_table_size; cpu_id++) {
        if (!_ebpf_epoch_cpu_table[cpu_id].non_preemtable_work_item)
            break;

        // Don't synchronize CPU's that have never participated.
        if (_ebpf_epoch_cpu_table[cpu_id].epoch == 0)
            continue;

        // Note: Either the per-cpu epoch or the global epoch could be out of date.
        // That is acceptable as it may schedule an extra work item.
        if (_ebpf_epoch_cpu_table[cpu_id].epoch != _ebpf_current_epoch)
            ebpf_queue_non_preemptable_work_item(_ebpf_epoch_cpu_table[cpu_id].non_preemtable_work_item, NULL);
    }

    return_value = ebpf_epoch_get_release_epoch(&released_epoch);
    if (return_value == EBPF_ERROR_SUCCESS) {
        ebpf_epoch_release_free_list(released_epoch);
    }
}

void*
ebpf_epoch_allocate(size_t size, ebpf_memory_type_t type)
{
    ebpf_epoch_allocation_header_t* header;
    size += sizeof(ebpf_epoch_allocation_header_t);
    header = (ebpf_epoch_allocation_header_t*)ebpf_allocate(size, type);
    if (header)
        header++;

    return header;
}

void
ebpf_epoch_free(void* memory)
{
    ebpf_epoch_allocation_header_t* header = (ebpf_epoch_allocation_header_t*)memory;
    ebpf_lock_state_t lock_state;
    header--;

    header->freed_epoch = ebpf_interlocked_increment_int64(&_ebpf_current_epoch) - 1;

    ebpf_lock_lock(&_ebpf_epoch_free_list_lock, &lock_state);
    header->next = _ebpf_epoch_free_list.next;
    _ebpf_epoch_free_list.next = header;
    ebpf_lock_unlock(&_ebpf_epoch_free_list_lock, &lock_state);
}

static void
ebpf_epoch_release_free_list(int64_t released_epoch)
{
    ebpf_lock_state_t lock_state;
    ebpf_epoch_allocation_header_t* header;
    ebpf_epoch_allocation_header_t* previous_header;

    ebpf_lock_lock(&_ebpf_epoch_free_list_lock, &lock_state);
    header = _ebpf_epoch_free_list.next;
    previous_header = &_ebpf_epoch_free_list;
    while (header) {
        if (header->freed_epoch <= released_epoch) {
            previous_header->next = header->next;
            ebpf_free(header);
            header = previous_header->next;
        } else {
            previous_header = header;
            header = header->next;
        }
    }
    ebpf_lock_unlock(&_ebpf_epoch_free_list_lock, &lock_state);
}

static ebpf_error_code_t
ebpf_epoch_get_release_epoch(int64_t* release_epoch)
{
    int64_t lowest_epoch = INT64_MAX;
    int64_t* thread_epoch;
    uint32_t cpu_id;
    uint64_t thread_id = 0;
    ebpf_lock_state_t lock_state;
    ebpf_error_code_t return_value;

    for (cpu_id = 1; cpu_id < _ebpf_epoch_cpu_table_size; cpu_id++) {
        if ((_ebpf_epoch_cpu_table[cpu_id].epoch != 0) && _ebpf_epoch_cpu_table[cpu_id].epoch < lowest_epoch)
            lowest_epoch = _ebpf_epoch_cpu_table[cpu_id].epoch;
    }

    ebpf_lock_lock(&_ebpf_epoch_thread_table_lock, &lock_state);
    return_value = ebpf_hash_table_next_key(_ebpf_epoch_thread_table, NULL, (uint8_t*)&thread_id);
    if (return_value == EBPF_ERROR_SUCCESS)
        for (;;) {
            return_value =
                ebpf_hash_table_lookup(_ebpf_epoch_thread_table, (uint8_t*)&thread_id, (uint8_t**)&thread_epoch);
            if (return_value != EBPF_ERROR_SUCCESS)
                break;

            if (*thread_epoch != 0 && *thread_epoch < lowest_epoch)
                lowest_epoch = *thread_epoch;

            return_value =
                ebpf_hash_table_next_key(_ebpf_epoch_thread_table, (uint8_t*)&thread_id, (uint8_t*)&thread_id);
            if (return_value != EBPF_ERROR_SUCCESS)
                break;
        }
    ebpf_lock_unlock(&_ebpf_epoch_thread_table_lock, &lock_state);

    if (return_value != EBPF_ERROR_NO_MORE_KEYS) {
        return return_value;
    }

    *release_epoch = lowest_epoch - 1;
    return EBPF_ERROR_SUCCESS;
}

static void
_ebpf_epoch_update_cpu_entry(void* context, void* parameter_1)
{
    ebpf_epoch_cpu_entry_t* cpu_entry = (ebpf_epoch_cpu_entry_t*)context;
    UNREFERENCED_PARAMETER(parameter_1);

    cpu_entry->epoch = _ebpf_current_epoch;
}
