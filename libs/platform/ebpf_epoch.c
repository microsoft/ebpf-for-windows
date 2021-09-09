// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"

// Brief summary of how epoch tracking works.
// Each free operation increments the _ebpf_current_epoch, the freed memory is stamped with that epoch, and the
// memory is inserted into a per-CPU free list.
//
// Each block of code that accesses epoch freed memory wraps access in calls to ebpf_epoch_enter/ebpf_epoch_exit.
//
// The per-CPU state is protected by a single per-CPU lock.
//
// ebpf_epoch_enter:
// The current epoch is recorded in either a per thread (preemptible) or per CPU (non-preemptible) ebpf_epoch_state_t
// and it is marked as active.
//
// ebpf_epoch_exit:
// First:
// The current epoch is recorded in either a per thread or per CPU ebpf_epoch_state_t and it is marked as inactive.
// For the per-thread case, the current CPUs per-thread table is first checked for an active epoch record. If not
// found then each CPUs per-thread table is checked until the active record is found. This deals with the case where
// a thread may switch CPUs between enter and exit.
//
// Second:
// Any entries in the per CPU free-list with epoch older than _ebpf_release_epoch are freed.
//
// Third:
// If the free-list still contains entries, the _ebpf_flush_timer is set (if not already set).
//
// ebpf_flush:
// Compute the global lowest epoch across all active CPU and thread ebpf_epoch_state_t and set _ebpf_release_epoch.
//
// _ebpf_flush_timer:
// Calls ebpf_flush and clears the _ebpf_flush_timer_set flag.
//

// Delay after the _ebpf_flush_timer is set before it runs.
#define EBPF_EPOCH_FLUSH_DELAY_IN_MICROSECONDS 1000

typedef struct _ebpf_epoch_state
{
    int64_t epoch;
    bool active;
} ebpf_epoch_state_t;

// Table to track per CPU state.
// This table must fit into a multiple of EBPF_CACHE_LINE_SIZE.
typedef struct _ebpf_epoch_cpu_entry
{
    ebpf_lock_t lock;
    _Requires_lock_held_(lock) ebpf_epoch_state_t cpu_epoch_state;
    _Requires_lock_held_(lock) ebpf_list_entry_t free_list;
    _Requires_lock_held_(lock) ebpf_hash_table_t* thread_table;
    struct
    {
        int timer_armed : 1;
    } flags;
    uintptr_t padding;
} ebpf_epoch_cpu_entry_t;

C_ASSERT(sizeof(ebpf_epoch_cpu_entry_t) % EBPF_CACHE_LINE_SIZE == 0);

static _Writable_elements_(_ebpf_epoch_cpu_count) ebpf_epoch_cpu_entry_t* _ebpf_epoch_cpu_table = NULL;
static uint32_t _ebpf_epoch_cpu_count = 0;

/**
 * @brief _ebpf_current_epoch indicates the newest active epoch. All memory free
 * operations were performed prior to this value.
 */
static volatile int64_t _ebpf_current_epoch = 1;
/**
 * @brief _ebpf_release_epoch indicates the newest inactive epoch. All memory
 * free operations performed prior to this value can be safely deleted.
 */
static volatile int64_t _ebpf_release_epoch = 0;

/**
 * @brief Flag to indicate that eBPF epoch tracker is shutting down.
 */
static bool _ebpf_epoch_rundown = false;

/**
 * @brief Timer used to update _ebpf_release_epoch.
 */
static ebpf_timer_work_item_t* _ebpf_flush_timer = NULL;

// There are two possible actions that can be taken at the end of an epoch.
// 1. Return a block of memory to the memory pool.
// 2. Invoke a work item, which is used to free custom allocations.
typedef enum _ebpf_epoch_allocation_type
{
    EBPF_EPOCH_ALLOCATION_MEMORY,
    EBPF_EPOCH_ALLOCATION_WORK_ITEM,
} ebpf_epoch_allocation_type_t;

typedef struct _ebpf_epoch_allocation_header
{
    ebpf_list_entry_t list_entry;
    int64_t freed_epoch;
    ebpf_epoch_allocation_type_t entry_type;
} ebpf_epoch_allocation_header_t;

/**
 * @brief This structure is used as a place holder when a custom action needs
 * to be performed on epoch end. Typically this is releasing memory that can't
 * be handled by the default allocator.
 */
typedef struct _ebpf_epoch_work_item
{
    ebpf_epoch_allocation_header_t header;
    void* callback_context;
    void (*callback)(void* context);
} ebpf_epoch_work_item_t;

static void
_ebpf_epoch_release_free_list(_In_ ebpf_epoch_cpu_entry_t* cpu_entry, int64_t released_epoch);

static ebpf_result_t
_ebpf_epoch_get_release_epoch(_Out_ int64_t* released_epoch);

static void
_ebpf_flush_worker(_In_ void* context);

ebpf_result_t
_ebpf_epoch_update_thread_state(uint32_t cpu_id, uintptr_t thread_id, int64_t current_epoch, bool enter);

ebpf_result_t
ebpf_epoch_initiate()
{
    ebpf_result_t return_value = EBPF_SUCCESS;
    uint32_t cpu_id;
    uint32_t cpu_count;

    cpu_count = ebpf_get_cpu_count();
    _ebpf_epoch_rundown = false;

    _ebpf_current_epoch = 1;
    _ebpf_release_epoch = 0;
    _ebpf_epoch_cpu_count = cpu_count;

    _ebpf_epoch_cpu_table = ebpf_allocate_cache_aligned(sizeof(ebpf_epoch_cpu_entry_t) * cpu_count);
    if (!_ebpf_epoch_cpu_table) {
        return_value = EBPF_NO_MEMORY;
        goto Error;
    }

    ebpf_assert(EBPF_CACHE_ALIGN_POINTER(_ebpf_epoch_cpu_table) == _ebpf_epoch_cpu_table);

    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        _ebpf_epoch_cpu_table[cpu_id].cpu_epoch_state.epoch = _ebpf_current_epoch;
        _ebpf_epoch_cpu_table[cpu_id].cpu_epoch_state.active = false;
        ebpf_lock_create(&_ebpf_epoch_cpu_table[cpu_id].lock);

        ebpf_list_initialize(&_ebpf_epoch_cpu_table[cpu_id].free_list);

        return_value = ebpf_hash_table_create(
            &_ebpf_epoch_cpu_table[cpu_id].thread_table,
            ebpf_allocate,
            ebpf_free,
            sizeof(uintptr_t),
            sizeof(ebpf_epoch_state_t),
            _ebpf_epoch_cpu_count,
            NULL);
        if (return_value != EBPF_SUCCESS) {
            goto Error;
        }
    }

    return_value = ebpf_allocate_timer_work_item(&_ebpf_flush_timer, _ebpf_flush_worker, NULL);
    if (return_value != EBPF_SUCCESS) {
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
    uint32_t cpu_id;

    ebpf_free_timer_work_item(_ebpf_flush_timer);
    _ebpf_flush_timer = NULL;

    _ebpf_epoch_rundown = true;
    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        _ebpf_epoch_release_free_list(&_ebpf_epoch_cpu_table[cpu_id], MAXINT64);
        ebpf_assert(ebpf_list_is_empty(&_ebpf_epoch_cpu_table[cpu_id].free_list));
        ebpf_lock_destroy(&_ebpf_epoch_cpu_table[cpu_id].lock);
        ebpf_hash_table_destroy(_ebpf_epoch_cpu_table[cpu_id].thread_table);
        _ebpf_epoch_cpu_table[cpu_id].thread_table = NULL;
    }
    _ebpf_epoch_cpu_count = 0;

    ebpf_free_cache_aligned(_ebpf_epoch_cpu_table);
}

ebpf_result_t
ebpf_epoch_enter()
{
    uint32_t current_cpu;
    current_cpu = ebpf_get_current_cpu();
    if (current_cpu >= _ebpf_epoch_cpu_count) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    if (ebpf_is_preemptible()) {
        return _ebpf_epoch_update_thread_state(current_cpu, ebpf_get_current_thread_id(), _ebpf_current_epoch, true);
    } else {
        ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);
        _ebpf_epoch_cpu_table[current_cpu].cpu_epoch_state.epoch = _ebpf_current_epoch;
        _ebpf_epoch_cpu_table[current_cpu].cpu_epoch_state.active = true;
        ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, state);
        return EBPF_SUCCESS;
    }
}

void
ebpf_epoch_exit()
{
    uint32_t current_cpu = ebpf_get_current_cpu();
    if (current_cpu >= _ebpf_epoch_cpu_count) {
        return;
    }

    if (ebpf_is_preemptible()) {
        _ebpf_epoch_update_thread_state(current_cpu, ebpf_get_current_thread_id(), _ebpf_current_epoch, false);
    } else {
        ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);
        _ebpf_epoch_cpu_table[current_cpu].cpu_epoch_state.epoch = _ebpf_current_epoch;
        _ebpf_epoch_cpu_table[current_cpu].cpu_epoch_state.active = false;
        ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, state);
    }

    // Reap the free list.
    if (!ebpf_list_is_empty(&_ebpf_epoch_cpu_table[current_cpu].free_list)) {
        _ebpf_epoch_release_free_list(&_ebpf_epoch_cpu_table[current_cpu], _ebpf_release_epoch);
    }
}

void
ebpf_epoch_flush()
{
    int64_t released_epoch;
    ebpf_result_t return_value = _ebpf_epoch_get_release_epoch(&released_epoch);
    if (return_value == EBPF_SUCCESS) {
        _ebpf_release_epoch = released_epoch;
    }
}

void*
ebpf_epoch_allocate(size_t size)
{
    ebpf_epoch_allocation_header_t* header;

    size += sizeof(ebpf_epoch_allocation_header_t);
    header = (ebpf_epoch_allocation_header_t*)ebpf_allocate(size);
    if (header)
        header++;

    return header;
}

void
ebpf_epoch_free(_Frees_ptr_opt_ void* memory)
{
    ebpf_epoch_allocation_header_t* header = (ebpf_epoch_allocation_header_t*)memory;
    ebpf_lock_state_t lock_state;
    uint32_t current_cpu;
    current_cpu = ebpf_get_current_cpu();
    if (current_cpu >= _ebpf_epoch_cpu_count) {
        return;
    }

    if (!memory)
        return;

    header--;
    if (_ebpf_epoch_rundown) {
        ebpf_free(header);
        return;
    }

    ebpf_assert(header->freed_epoch == 0);
    header->entry_type = EBPF_EPOCH_ALLOCATION_MEMORY;

    // Items are inserted into the free list in increasing epoch order.
    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);
    header->freed_epoch = ebpf_interlocked_increment_int64(&_ebpf_current_epoch) - 1;
    ebpf_list_insert_tail(&_ebpf_epoch_cpu_table[current_cpu].free_list, &header->list_entry);
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, lock_state);
}

ebpf_epoch_work_item_t*
ebpf_epoch_allocate_work_item(_In_ void* callback_context, _In_ void (*callback)(void* context))
{
    ebpf_epoch_work_item_t* work_item = ebpf_allocate(sizeof(ebpf_epoch_work_item_t));
    if (!work_item) {
        return NULL;
    }

    work_item->callback = callback;
    work_item->callback_context = callback_context;
    work_item->header.entry_type = EBPF_EPOCH_ALLOCATION_WORK_ITEM;

    return work_item;
}

void
ebpf_epoch_schedule_work_item(_In_ ebpf_epoch_work_item_t* work_item)
{
    ebpf_lock_state_t lock_state;
    uint32_t current_cpu;
    current_cpu = ebpf_get_current_cpu();
    if (current_cpu >= _ebpf_epoch_cpu_count) {
        return;
    }

    if (_ebpf_epoch_rundown) {
        work_item->callback(work_item->callback_context);
        return;
    }

    // Items are inserted into the free list in increasing epoch order.
    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);
    work_item->header.freed_epoch = ebpf_interlocked_increment_int64(&_ebpf_current_epoch) - 1;
    ebpf_list_insert_tail(&_ebpf_epoch_cpu_table[current_cpu].free_list, &work_item->header.list_entry);
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, lock_state);
}

void
ebpf_epoch_free_work_item(_Frees_ptr_opt_ ebpf_epoch_work_item_t* work_item)
{
    ebpf_lock_state_t lock_state;
    uint32_t current_cpu;
    current_cpu = ebpf_get_current_cpu();
    if (current_cpu >= _ebpf_epoch_cpu_count) {
        return;
    }
    if (!work_item) {
        return;
    }

    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);
    ebpf_list_remove_entry(&work_item->header.list_entry);
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, lock_state);
    ebpf_free(work_item);
}

/**
 * @brief Remove all entries from the per-CPU free list that have an epoch that is before released_epoch.
 *
 * @param[in] cpu_id The per-CPU free list to search.
 * @param[in] released_epoch The epoch to release.
 */
static void
_ebpf_epoch_release_free_list(_In_ ebpf_epoch_cpu_entry_t* cpu_entry, int64_t released_epoch)
{
    ebpf_lock_state_t lock_state;
    ebpf_list_entry_t* entry;
    ebpf_epoch_allocation_header_t* header;
    ebpf_list_entry_t free_list;

    ebpf_list_initialize(&free_list);

    // Move all expired items to the free list.
    lock_state = ebpf_lock_lock(&cpu_entry->lock);
    while (!ebpf_list_is_empty(&cpu_entry->free_list)) {
        entry = cpu_entry->free_list.Flink;
        header = CONTAINING_RECORD(entry, ebpf_epoch_allocation_header_t, list_entry);
        if (header->freed_epoch <= released_epoch) {
            ebpf_list_remove_entry(entry);
            ebpf_list_insert_tail(&free_list, entry);
        } else {
            break;
        }
    }
    // If there are still items in the free list, schedule a timer to reap them in the future.
    if (!ebpf_list_is_empty(&cpu_entry->free_list) && !cpu_entry->flags.timer_armed) {
        // We will arm the timer once per CPU that sees entries it can't release.
        // That's acceptable as arming the timer is idempotent.
        cpu_entry->flags.timer_armed = true;
        ebpf_schedule_timer_work_item(_ebpf_flush_timer, EBPF_EPOCH_FLUSH_DELAY_IN_MICROSECONDS);
    }

    ebpf_lock_unlock(&cpu_entry->lock, lock_state);

    // Free all the expired items outside of the lock.
    while (!ebpf_list_is_empty(&free_list)) {
        entry = free_list.Flink;
        header = CONTAINING_RECORD(entry, ebpf_epoch_allocation_header_t, list_entry);
        ebpf_list_remove_entry(entry);
        switch (header->entry_type) {
        case EBPF_EPOCH_ALLOCATION_MEMORY:
            ebpf_free(header);
            break;
        case EBPF_EPOCH_ALLOCATION_WORK_ITEM: {
            ebpf_epoch_work_item_t* work_item = CONTAINING_RECORD(header, ebpf_epoch_work_item_t, header);
            work_item->callback(work_item->callback_context);
            break;
        }
        }
    }
}

/**
 * @brief Determine the newest inactive epoch and return it.
 *
 * @param[out] release_epoch The newest inactive epoch.
 * @retval EBPF_SUCCESS Found the newest inactive epoch.
 * @retval EBPF_NO_MEMORY Insufficient memory to complete this operation.
 */
static ebpf_result_t
_ebpf_epoch_get_release_epoch(_Out_ int64_t* release_epoch)
{
    // Grab an non-authoritative version of _ebpf_current_epoch.
    // Note: If there are no active threads or non-preemptible work items then we need to assign
    // an epoch that is guaranteed to be older than any thread that starts after this point.
    // Grabbing the current epoch guarantees that, even if we have a stale value of _ebpf_current_epoch.
    int64_t lowest_epoch = _ebpf_current_epoch;
    uint32_t cpu_id;
    ebpf_lock_state_t lock_state;
    ebpf_result_t return_value;

    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_epoch_state_t* thread_epoch_state = NULL;
        uintptr_t thread_id = 0;

        // Grab the CPU epoch.
        lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].lock);

        // Clear the flush timer flag.
        _ebpf_epoch_cpu_table[cpu_id].flags.timer_armed = false;

        if (_ebpf_epoch_cpu_table[cpu_id].cpu_epoch_state.active) {
            lowest_epoch = min(lowest_epoch, _ebpf_epoch_cpu_table[cpu_id].cpu_epoch_state.epoch);
        }

        // Loop over all the threads in this CPU entry.
        do {
            // Get the next per-thread entry from this CPU.
            return_value = ebpf_hash_table_next_key_and_value(
                _ebpf_epoch_cpu_table[cpu_id].thread_table,
                thread_id == 0 ? NULL : (uint8_t*)&thread_id,
                (uint8_t*)&thread_id,
                (uint8_t**)&thread_epoch_state);

            if (return_value != EBPF_SUCCESS) {
                break;
            }
            if (thread_epoch_state->active) {
                lowest_epoch = min(lowest_epoch, thread_epoch_state->epoch);
            }
        } while (return_value == EBPF_SUCCESS);

        ebpf_lock_unlock(&_ebpf_epoch_cpu_table[cpu_id].lock, lock_state);
        if (return_value != EBPF_NO_MORE_KEYS) {
            goto Exit;
        }
        return_value = EBPF_SUCCESS;
    }

    return_value = EBPF_SUCCESS;

Exit:

    *release_epoch = lowest_epoch - 1;
    return return_value;
}

/**
 * @brief Routine executed on a timer to compute the newest inactive epoch.
 *
 * @param[in] context Unused.
 */
static void
_ebpf_flush_worker(_In_ void* context)
{
    UNREFERENCED_PARAMETER(context);

    ebpf_epoch_flush();
}

ebpf_result_t
_ebpf_epoch_update_thread_state(uint32_t cpu_id, uintptr_t thread_id, int64_t current_epoch, bool enter)
{
    ebpf_result_t return_value;
    ebpf_lock_state_t lock_state;
    ebpf_epoch_state_t* thread_epoch;
    ebpf_epoch_state_t local_thread_epoch = {current_epoch, true};
    bool active_entry_found = false;
    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].lock);
    return_value = ebpf_hash_table_find(
        _ebpf_epoch_cpu_table[cpu_id].thread_table, (uint8_t*)&thread_id, (uint8_t**)&thread_epoch);
    if (return_value == EBPF_SUCCESS) {
        if (enter) {
            thread_epoch->epoch = current_epoch;
            thread_epoch->active = true;
        } else {
            // https://github.com/microsoft/ebpf-for-windows/issues/437
            // Consider pruning inactive entries.
            if (thread_epoch->active) {
                thread_epoch->active = false;
                active_entry_found = true;
            }
        }
        return_value = EBPF_SUCCESS;
    } else if (return_value == EBPF_KEY_NOT_FOUND) {
        return_value = ebpf_hash_table_update(
            _ebpf_epoch_cpu_table[cpu_id].thread_table,
            (const uint8_t*)&thread_id,
            (const uint8_t*)&local_thread_epoch,
            EBPF_HASH_TABLE_OPERATION_INSERT);
    }
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[cpu_id].lock, lock_state);

    if (return_value == EBPF_SUCCESS) {
        goto Exit;
    }

    if (enter) {
        goto Exit;
    }

    // If this is an exit call and the current CPU doesn't have the active entry
    // then scan all CPUs until we find it.
    if (!active_entry_found) {
        for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
            lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].lock);
            return_value = ebpf_hash_table_find(
                _ebpf_epoch_cpu_table[cpu_id].thread_table, (uint8_t*)&thread_id, (uint8_t**)&thread_epoch);
            ebpf_lock_unlock(&_ebpf_epoch_cpu_table[cpu_id].lock, lock_state);

            if (return_value == EBPF_SUCCESS && thread_epoch->active) {
                thread_epoch->active = false;
                active_entry_found = true;
                break;
            }
        }
    }
    ebpf_assert(active_entry_found);

Exit:
    return return_value;
}
