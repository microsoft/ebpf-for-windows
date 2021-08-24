// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"

// Brief summary of how epoch tracking works.
// Each free operation increments the epoch and the freed memory is stamped with
// that epoch.
//
// Each block of code that accesses epoch freed memory wraps access in calls to
// ebpf_epoch_enter/ebpf_epoch_exit.
//
// Epoch tracking is handled differently for preemptible vs non-preemptible
// invocations.
//
// Non-preemptible invocations behavior:
// 1) During ebpf_epoch_enter and ebpf_epoch_exit the value of _ebpf_current_epoch is captured in the
// _ebpf_epoch_cpu_table[cpu_id].non_preemptible_epoch field.
// 2) This field is read/written with out explicit synchronization and can be old.
// 3) _ebpf_epoch_update_cpu_entry periodically updates this on idle CPUs.
//
// Preemptible invocations behavior:
// 1) During ebpf_epoch_enter the value of _ebpf_current_epoch is captured and stored in the
// _ebpf_epoch_cpu_table[cpu_id].thread_table[thread_id].entry_epoch field.
// 2) During ebpf_epoch_exit the value of _ebpf_current_epoch is captured and stored in the
// _ebpf_epoch_cpu_table[cpu_id].thread_table[thread_id].exit_epoch field.
// 3) The _ebpf_epoch_cpu_table[cpu_id].thread_table is protected by _ebpf_epoch_cpu_table[cpu_id].thread_table_lock.
// 4) If and only if entry_epoch > exit_epoch then the thread is actively executing between calls to ebpf_epoch_enter
// and ebpf_epoch_exit.
//
// Common behavior:
// 1) Calls to ebpf_epoch_free mark the memory with _ebpf_current_epoch, atomically increment it and insert the memory
// into the _ebpf_epoch_cpu_table[cpu_id].free_list while holding the _ebpf_epoch_cpu_table[cpu_id].free_list_lock.
// 2) During ebpf_epoch_exit all entries in _ebpf_epoch_cpu_table[cpu_id].free_list where freed_epoch <
// _ebpf_release_epoch are freed using ebpf_free.
// 3) During ebpf_epoch_flush the minimum epoch is computed across the values in
// _ebpf_epoch_cpu_table[*].non_preemptible_epoch and  _ebpf_epoch_cpu_table[*].thread_table[*].entry_epoch (for active
// threads) and then written to _ebpf_release_epoch.
// 4) ebpf_epoch_flush is called periodically by _ebpf_flush_timer.
// 5) ebpf_epoch_flush also queues a non-preemptible work-item (_ebpf_epoch_update_cpu_entry) to all CPUs where
// _ebpf_epoch_cpu_table[cpu_id].non_preemptible_epoch != _ebpf_current_epoch.
// 6) _ebpf_epoch_update_cpu_entry calls ebpf_epoch_enter/ebpf_epoch_exit.
//
// Note:
// CPU table entries aren't cleared on exit as we can't rely on memory ordering.
// I.e., the thread doing the cleanup may have a stale view of the CPU table.
// As long as the entries in the CPU table increase, this gives correct behavior.
//

// Frequency to compute newest inactive epoch.
#define EBPF_EPOCH_FLUSH_DELAY_IN_MICROSECONDS 1000

typedef struct _ebpf_epoch_thread_entry
{
    int64_t entry_epoch;
    int64_t exit_epoch;
} ebpf_epoch_thread_entry_t;

// Table to track per CPU state.
typedef struct _ebpf_epoch_cpu_entry
{
    // Discussion: https://github.com/microsoft/ebpf-for-windows/discussions/442
    // Should this be split into an entry/exit epoch + lock?
    int64_t non_preemptible_epoch;
    ebpf_non_preemptible_work_item_t* non_preemptible_work_item;
    // Discussion: https://github.com/microsoft/ebpf-for-windows/discussions/438
    // Should this code switch to using an InterlockedSList?
    ebpf_lock_t free_list_lock;
    _Requires_lock_held_(free_list_lock) ebpf_list_entry_t free_list;
    // Discussion: https://github.com/microsoft/ebpf-for-windows/discussions/440
    // Should this code switch to a lock-free hash table?
    ebpf_lock_t thread_table_lock;
    _Requires_lock_held_(thread_table_lock) ebpf_hash_table_t* thread_table;
} ebpf_epoch_cpu_entry_t;

static _Writable_elements_(_ebpf_epoch_cpu_count) ebpf_epoch_cpu_entry_t* _ebpf_epoch_cpu_table = NULL;
static uint32_t _ebpf_epoch_cpu_count = 0;

/**
 * @brief _ebpf_current_epoch indicates the newest active epoch. All memory free
 * operations were performed prior to this value.
 *
 */
static volatile int64_t _ebpf_current_epoch = 1;
/**
 * @brief _ebpf_release_epoch indicates the newest inactive epoch. All memory
 * free operations performed prior to this value can be safely deleted.
 *
 */
static volatile int64_t _ebpf_release_epoch = 0;

/**
 * @brief Flag to indicate that eBPF epoch tracker is shutting down.
 *
 */
static bool _ebpf_epoch_rundown = false;

/**
 * @brief Timer used to update _ebpf_release_epoch.
 *
 */
static ebpf_timer_work_item_t* _ebpf_flush_timer = NULL;
static volatile int32_t _ebpf_flush_timer_set = 0;

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

static bool _ebpf_epoch_initiated = false;

static void
_ebpf_epoch_release_free_list(ebpf_epoch_cpu_entry_t* cpu_entry, int64_t released_epoch);

static ebpf_result_t
_ebpf_epoch_get_release_epoch(_Out_ int64_t* released_epoch);

static void
_ebpf_epoch_update_cpu_entry(_In_ void* context, _In_ void* parameter_1);

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
    _ebpf_epoch_initiated = true;
    _ebpf_epoch_rundown = false;

    _ebpf_current_epoch = 1;
    _ebpf_epoch_cpu_count = cpu_count;

    _ebpf_epoch_cpu_table = ebpf_allocate(_ebpf_epoch_cpu_count * sizeof(ebpf_epoch_cpu_entry_t));
    if (!_ebpf_epoch_cpu_table) {
        return_value = EBPF_NO_MEMORY;
        goto Error;
    }

    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        _ebpf_epoch_cpu_table[cpu_id].non_preemptible_epoch = _ebpf_current_epoch;

        ebpf_list_initialize(&_ebpf_epoch_cpu_table[cpu_id].free_list);
        ebpf_lock_create(&_ebpf_epoch_cpu_table[cpu_id].free_list_lock);

        if (ebpf_is_non_preemptible_work_item_supported()) {
            ebpf_non_preemptible_work_item_t* work_item_context = NULL;
            return_value = ebpf_allocate_non_preemptible_work_item(
                &work_item_context, cpu_id, _ebpf_epoch_update_cpu_entry, &_ebpf_epoch_cpu_table[cpu_id]);

            if (return_value != EBPF_SUCCESS) {
                goto Error;
            }
            _ebpf_epoch_cpu_table[cpu_id].non_preemptible_work_item = work_item_context;
        }

        ebpf_lock_create(&_ebpf_epoch_cpu_table[cpu_id].thread_table_lock);
        return_value = ebpf_hash_table_create(
            &_ebpf_epoch_cpu_table[cpu_id].thread_table,
            ebpf_allocate,
            ebpf_free,
            sizeof(uintptr_t),
            sizeof(ebpf_epoch_thread_entry_t),
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

    if (!_ebpf_epoch_initiated)
        return;

    if (ebpf_is_non_preemptible_work_item_supported()) {
        for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
            ebpf_free_non_preemptible_work_item(_ebpf_epoch_cpu_table[cpu_id].non_preemptible_work_item);
            _ebpf_epoch_cpu_table[cpu_id].non_preemptible_work_item = NULL;
        }
    }

    ebpf_free_timer_work_item(_ebpf_flush_timer);
    _ebpf_epoch_rundown = true;
    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        _ebpf_epoch_release_free_list(&_ebpf_epoch_cpu_table[cpu_id], MAXINT64);
        ebpf_assert(ebpf_list_is_empty(&_ebpf_epoch_cpu_table[cpu_id].free_list));
        ebpf_lock_destroy(&_ebpf_epoch_cpu_table[cpu_id].free_list_lock);
        ebpf_lock_destroy(&_ebpf_epoch_cpu_table[cpu_id].thread_table_lock);
        ebpf_hash_table_destroy(_ebpf_epoch_cpu_table[cpu_id].thread_table);
        _ebpf_epoch_cpu_table[cpu_id].thread_table = NULL;
    }

    _ebpf_epoch_cpu_count = 0;

    ebpf_free(_ebpf_epoch_cpu_table);
    _ebpf_epoch_initiated = false;
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
        _ebpf_epoch_cpu_table[current_cpu].non_preemptible_epoch = _ebpf_current_epoch;
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
        _ebpf_epoch_cpu_table[current_cpu].non_preemptible_epoch = _ebpf_current_epoch;
    }

    if (!ebpf_list_is_empty(&_ebpf_epoch_cpu_table[current_cpu].free_list) &&
        (ebpf_interlocked_compare_exchange_int32(&_ebpf_flush_timer_set, 1, 0) == 0)) {
        ebpf_schedule_timer_work_item(_ebpf_flush_timer, EBPF_EPOCH_FLUSH_DELAY_IN_MICROSECONDS);
    }

    if (!ebpf_list_is_empty(&_ebpf_epoch_cpu_table[current_cpu].free_list)) {
        _ebpf_epoch_release_free_list(&_ebpf_epoch_cpu_table[current_cpu], _ebpf_release_epoch);
    }
}

void
ebpf_epoch_flush()
{
    ebpf_result_t return_value;
    int64_t released_epoch;
    uint32_t cpu_id;

    return_value = _ebpf_epoch_get_release_epoch(&released_epoch);
    if (return_value == EBPF_SUCCESS) {
        _ebpf_release_epoch = released_epoch, _ebpf_current_epoch;
    }

    if (ebpf_is_non_preemptible_work_item_supported()) {
        // Schedule a non-preemptible work item to bring the CPU up to the current
        // epoch.
        // Note: May not affect the current flush.
        for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
            // Note: Either the per-cpu epoch or the global epoch could be out of date.
            // That is acceptable as it may schedule an extra work item.
            if (_ebpf_epoch_cpu_table[cpu_id].non_preemptible_epoch != _ebpf_current_epoch)
                ebpf_queue_non_preemptible_work_item(_ebpf_epoch_cpu_table[cpu_id].non_preemptible_work_item, NULL);
        }
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
ebpf_epoch_free(_In_ void* memory)
{
    ebpf_epoch_allocation_header_t* header = (ebpf_epoch_allocation_header_t*)memory;
    ebpf_lock_state_t lock_state;
    uint32_t current_cpu;
    current_cpu = ebpf_get_current_cpu();
    if (current_cpu >= _ebpf_epoch_cpu_count) {
        return;
    }

    ebpf_assert(_ebpf_epoch_initiated);

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
    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].free_list_lock);
    header->freed_epoch = ebpf_interlocked_increment_int64(&_ebpf_current_epoch) - 1;
    ebpf_list_insert_tail(&_ebpf_epoch_cpu_table[current_cpu].free_list, &header->list_entry);
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].free_list_lock, lock_state);
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
    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].free_list_lock);
    work_item->header.freed_epoch = ebpf_interlocked_increment_int64(&_ebpf_current_epoch) - 1;
    ebpf_list_insert_tail(&_ebpf_epoch_cpu_table[current_cpu].free_list, &work_item->header.list_entry);
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].free_list_lock, lock_state);
}

void
ebpf_epoch_free_work_item(_In_ ebpf_epoch_work_item_t* work_item)
{
    ebpf_lock_state_t lock_state;
    uint32_t current_cpu;
    current_cpu = ebpf_get_current_cpu();
    if (current_cpu >= _ebpf_epoch_cpu_count) {
        return;
    }

    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].free_list_lock);
    ebpf_list_remove_entry(&work_item->header.list_entry);
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].free_list_lock, lock_state);
    ebpf_free(work_item);
}

/**
 * @brief Remove all entries from the per-CPU free list that have an epoch that is before released_epoch.
 *
 * @param[in] cpu_id The per-CPU free list to search.
 * @param[in] released_epoch The epoch to release.
 */
static void
_ebpf_epoch_release_free_list(ebpf_epoch_cpu_entry_t* cpu_entry, int64_t released_epoch)
{
    ebpf_lock_state_t lock_state;
    ebpf_list_entry_t* entry;
    ebpf_epoch_allocation_header_t* header;
    ebpf_list_entry_t free_list;

    ebpf_list_initialize(&free_list);

    // Move all expired items to the free list.
    lock_state = ebpf_lock_lock(&cpu_entry->free_list_lock);
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
    ebpf_lock_unlock(&cpu_entry->free_list_lock, lock_state);

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
    ebpf_assert(ebpf_list_is_empty(&cpu_entry->free_list) || !_ebpf_epoch_rundown);
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
    // Grab an authoritative version of _ebpf_current_epoch.
    // Note: If there are no active threads or non-preemptible work items then we need to assign
    // an epoch that is guaranteed to be older than any thread that starts after this point.
    // Grabbing the current epoch guarantees that.
    int64_t lowest_epoch = ebpf_interlocked_increment_int64(&_ebpf_current_epoch);
    uint32_t cpu_id;
    ebpf_lock_state_t lock_state;
    ebpf_result_t return_value;
    ebpf_hash_table_t* per_thread_epoch_table = NULL;

    return_value = ebpf_hash_table_create(
        &per_thread_epoch_table,
        ebpf_allocate,
        ebpf_free,
        sizeof(uintptr_t),
        sizeof(ebpf_epoch_thread_entry_t),
        _ebpf_epoch_cpu_count,
        NULL);

    if (return_value != EBPF_SUCCESS) {
        goto Exit;
    }

    // Gather the lowest epoch from non-preemptible work items that may have run.
    // If the platform supports non-preemtible work items, check the per-CPU epochs.
    if (ebpf_is_non_preemptible_work_item_supported()) {
        for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
            lowest_epoch = min(lowest_epoch, _ebpf_epoch_cpu_table[cpu_id].non_preemptible_epoch);
        }
    }

    // Gather highest entry/exit epoch this thread has seen across all CPUs.
    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_epoch_thread_entry_t* thread_entry = NULL;
        uintptr_t thread_id = 0;
        // Check each per-CPU thread state.
        lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].thread_table_lock);
        while (return_value == EBPF_SUCCESS) {
            ebpf_epoch_thread_entry_t* new_thread_entry = NULL;
            ebpf_result_t local_result;
            // Get the next per-thread entry from this CPU.
            return_value = ebpf_hash_table_next_key_and_value(
                _ebpf_epoch_cpu_table[cpu_id].thread_table,
                thread_id == 0 ? NULL : (uint8_t*)&thread_id,
                (uint8_t*)&thread_id,
                (uint8_t**)&thread_entry);

            if (return_value != EBPF_SUCCESS) {
                break;
            }

            // Check if this thread is already present in the global thread table.
            local_result =
                ebpf_hash_table_find(per_thread_epoch_table, (uint8_t*)&thread_id, (uint8_t**)&new_thread_entry);
            if (local_result == EBPF_KEY_NOT_FOUND) {
                // Not found, insert a copy of the per-CPU entry.
                return_value = ebpf_hash_table_update(
                    per_thread_epoch_table,
                    (uint8_t*)&thread_id,
                    (uint8_t*)thread_entry,
                    NULL,
                    EBPF_HASH_TABLE_OPERATION_INSERT);
            } else if (local_result == EBPF_SUCCESS) {
                // Found, merge the global and per-CPU entry.
                new_thread_entry->entry_epoch = max(new_thread_entry->entry_epoch, thread_entry->entry_epoch);
                new_thread_entry->exit_epoch = max(new_thread_entry->exit_epoch, thread_entry->exit_epoch);
            }
        };
        ebpf_lock_unlock(&_ebpf_epoch_cpu_table[cpu_id].thread_table_lock, lock_state);
        if (return_value != EBPF_NO_MORE_KEYS) {
            goto Exit;
        }
        return_value = EBPF_SUCCESS;
    }

    // Gather the lowest epoch from threads that are actively running.
    // Thread is active if and only if entry_epoch > exit_epoch.
    uintptr_t thread_id = 0;
    while (return_value == EBPF_SUCCESS) {
        ebpf_epoch_thread_entry_t* thread_entry = NULL;
        return_value = ebpf_hash_table_next_key_and_value(
            per_thread_epoch_table,
            thread_id == 0 ? NULL : (uint8_t*)&thread_id,
            (uint8_t*)&thread_id,
            (uint8_t**)&thread_entry);

        if (return_value == EBPF_SUCCESS) {
            // Only consider the thread if it is active.
            if (thread_entry->entry_epoch > thread_entry->exit_epoch) {
                lowest_epoch = min(lowest_epoch, thread_entry->entry_epoch);
            }
        }
    }
    if (return_value != EBPF_NO_MORE_KEYS) {
        goto Exit;
    }

    return_value = EBPF_SUCCESS;

Exit:

    *release_epoch = lowest_epoch - 1;
    return return_value;
}

/**
 * @brief Helper function to bring this CPU up to the current epoch and flush free list.
 *
 * @param[in] context Not used.
 * @param[in] parameter_1 Not used.
 */
static void
_ebpf_epoch_update_cpu_entry(_In_ void* context, _In_ void* parameter_1)
{
    ebpf_epoch_cpu_entry_t* cpu_entry = (ebpf_epoch_cpu_entry_t*)context;
    UNREFERENCED_PARAMETER(parameter_1);

    cpu_entry->non_preemptible_epoch = _ebpf_current_epoch;
    if (!ebpf_list_is_empty(&cpu_entry->free_list)) {
        _ebpf_epoch_release_free_list(cpu_entry, _ebpf_release_epoch);
    }
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
    ebpf_interlocked_compare_exchange_int32(&_ebpf_flush_timer_set, 0, 1);
}

ebpf_result_t
_ebpf_epoch_update_thread_state(uint32_t cpu_id, uintptr_t thread_id, int64_t current_epoch, bool enter)
{
    ebpf_result_t return_value;
    ebpf_lock_state_t lock_state;
    ebpf_epoch_thread_entry_t* thread_state;
    ebpf_epoch_thread_entry_t local_thread_state = {enter ? current_epoch : 0, !enter ? current_epoch : 0};
    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].thread_table_lock);
    return_value = ebpf_hash_table_find(
        _ebpf_epoch_cpu_table[cpu_id].thread_table, (uint8_t*)&thread_id, (uint8_t**)&thread_state);
    if (return_value == EBPF_SUCCESS) {
        if (enter) {
            thread_state->entry_epoch = current_epoch;
        } else {
            thread_state->exit_epoch = current_epoch;
        }
        return_value = EBPF_SUCCESS;
    } else if (return_value == EBPF_KEY_NOT_FOUND) {
        return_value = ebpf_hash_table_update(
            _ebpf_epoch_cpu_table[cpu_id].thread_table,
            (const uint8_t*)&thread_id,
            (const uint8_t*)&local_thread_state,
            NULL,
            EBPF_HASH_TABLE_OPERATION_INSERT);
    }
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[cpu_id].thread_table_lock, lock_state);

    if (return_value == EBPF_SUCCESS) {
        goto Exit;
    }

    if (enter) {
        goto Exit;
    }

    // This can only fail on out of memory.
    ebpf_assert(return_value == EBPF_NO_MEMORY);

    // Failed to insert on exit.
    // There must be an existing thread entry for this thread on another CPU.
    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].thread_table_lock);
        return_value = ebpf_hash_table_find(
            _ebpf_epoch_cpu_table[cpu_id].thread_table, (uint8_t*)&thread_id, (uint8_t**)&thread_state);
        if (return_value == EBPF_SUCCESS) {
            thread_state->exit_epoch = current_epoch;
        }
        ebpf_lock_unlock(&_ebpf_epoch_cpu_table[cpu_id].thread_table_lock, lock_state);
        if (thread_state) {
            break;
        }
    }
    // There must be at least 1 thread_state created on entry.
    ebpf_assert(thread_state);

Exit:
    return return_value;
}
