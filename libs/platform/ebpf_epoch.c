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
// If preemptible, the thread is affinitized to the current CPU (to prevent it from moving between CPUs).
// Either the per-CPU or per-thread ebpf_epoch_state_t is located.
// The ebpf_epoch_state_t is marked as active and the current epoch is recorded and last_used_time is set to now.
//
// ebpf_epoch_exit:
// First:
// Either the per-CPU or per-thread ebpf_epoch_state_t is located.
// The ebpf_epoch_state_t is marked as inactive and the current epoch is recorded and last_used_time is set to now.
// If preemptible, the thread is affinity is restored.
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
// _ebpf_epoch_stale_worker:
// Called if a CPU has items to be freed, but hasn't run anything in EBPF_EPOCH_FLUSH_DELAY_IN_MICROSECONDS.
//
// Stale flag:
// The stale flag is set if the timer runs and the ebpf_epoch_cpu_entry_t has entries in its free list.
// If the stale flag is already set, then the per-CPU stale_worker is scheduled.

// Delay after the _ebpf_flush_timer is set before it runs.
#define EBPF_EPOCH_FLUSH_DELAY_IN_MICROSECONDS 1000

// Time before logging that a thread entry is stale
#define EBPF_EPOCH_STALE_THREAD_TIME_IN_NANO_SECONDS 10000000000 // 10 seconds

typedef struct _ebpf_epoch_state
{
    int64_t epoch;           // The highest epoch seen by this epoch state.
    bool active : 1;         // Currently within an entry/exit block.
    bool timer_armed : 1;    // This state has requested the global timer.
    bool stale : 1;          // This state has entries that haven't been freed.
    bool timer_disabled : 1; // Prevent re-arming the timer during shutdown.
} ebpf_epoch_state_t;

// Table to track per CPU state.
// This table must fit into a multiple of EBPF_CACHE_LINE_SIZE.
typedef struct _ebpf_epoch_cpu_entry
{
    ebpf_lock_t lock;
    _Requires_lock_held_(lock) ebpf_epoch_state_t epoch_state;                 // Per-CPU epoch state.
    _Requires_lock_held_(lock) ebpf_list_entry_t free_list;                    // Per-CPU free list.
    _Requires_lock_held_(lock) ebpf_hash_table_t* thread_table;                // Per-CPU thread table.
    _Requires_lock_held_(lock) ebpf_non_preemptible_work_item_t* stale_worker; // Per-CPU stale worker DPC.
    uint32_t padding; // Pad to multiple of EBPF_CACHE_LINE_SIZE.
} ebpf_epoch_cpu_entry_t;

typedef struct _ebpf_epoch_thread_entry
{
    ebpf_epoch_state_t epoch_state;     // Per-thread epoch state.
    uintptr_t old_thread_affinity_mask; // Thread affinity mask before entering an entry/exit block.
    uint64_t last_used_time;            // Time when this entry was last used.
} ebpf_epoch_thread_entry_t;

C_ASSERT(sizeof(ebpf_epoch_cpu_entry_t) % EBPF_CACHE_LINE_SIZE == 0); // Verify alignment.

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
static volatile bool _ebpf_epoch_rundown = false;

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

typedef enum _ebpf_epoch_get_thread_entry_option
{
    EBPF_EPOCH_GET_THREAD_ENTRY_OPTION_CREATE_IF_NOT_FOUND,
    EBPF_EPOCH_GET_THREAD_ENTRY_OPTION_DO_NOT_CREATE,
} ebpf_epoch_get_thread_entry_option_t;

/**
 * @brief Remove all entries from the per-CPU free list that have an epoch that is before released_epoch.
 *
 * @param[in] cpu_id The per-CPU free list to search.
 * @param[in] released_epoch The epoch to release.
 */
static void
_ebpf_epoch_release_free_list(_In_ ebpf_epoch_cpu_entry_t* cpu_entry, int64_t released_epoch);

/**
 * @brief Determine the newest inactive epoch and return it.
 *
 * @param[out] release_epoch The newest inactive epoch.
 * @retval EBPF_SUCCESS Found the newest inactive epoch.
 * @retval EBPF_NO_MEMORY Insufficient memory to complete this operation.
 */
static ebpf_result_t
_ebpf_epoch_get_release_epoch(_Out_ int64_t* released_epoch);

/**
 * @brief Routine executed on a timer to compute the newest inactive epoch.
 *
 * @param[in] context Unused.
 */
static void
_ebpf_flush_worker(_In_ void* context);

/**
 * @brief Flush any stale entries from the per-CPU free list.
 *
 * @param[in] work_item_context Unused.
 * @param[in] parameter_1 Unused.
 */
static void
_ebpf_epoch_stale_worker(_In_ void* work_item_context, _In_ void* parameter_1);

/**
 * @brief Find or create a thread entry for the current thread.
 * @param[in] cpu_id The CPU id of the current thread.
 * @param[in] thread_id The thread id of the current thread.
 * @param[in] option The option to use when creating the thread entry.
 * @return A pointer to the thread entry.
 */
static _Requires_lock_held_(_ebpf_epoch_cpu_table[cpu_id].lock) ebpf_epoch_thread_entry_t* _ebpf_epoch_get_thread_entry(
    uint32_t cpu_id, uintptr_t thread_id, ebpf_epoch_get_thread_entry_option_t option);

/**
 * @brief Arm the flush timer if:
 *  Timer is not already armed.
 *  Timer is not disabled.
 *  Free list is not empty.
 */
static _Requires_lock_held_(cpu_entry->lock) void _ebpf_epoch_arm_timer_if_needed(ebpf_epoch_cpu_entry_t* cpu_entry);

ebpf_result_t
ebpf_epoch_initiate()
{
    EBPF_LOG_ENTRY();
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
        _ebpf_epoch_cpu_table[cpu_id].epoch_state.epoch = _ebpf_current_epoch;
        _ebpf_epoch_cpu_table[cpu_id].epoch_state.active = false;
        ebpf_lock_create(&_ebpf_epoch_cpu_table[cpu_id].lock);

        ebpf_list_initialize(&_ebpf_epoch_cpu_table[cpu_id].free_list);

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
    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_epoch_terminate()
{
    EBPF_LOG_ENTRY();
    uint32_t cpu_id;

    _ebpf_epoch_rundown = true;

    // First disable all timers.
    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_lock_state_t lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].lock);
        _ebpf_epoch_cpu_table[cpu_id].epoch_state.timer_disabled = true;
        ebpf_lock_unlock(&_ebpf_epoch_cpu_table[cpu_id].lock, lock_state);
    }

    // Cancel and wait for any currently executing timers and then free the timer.
    ebpf_free_timer_work_item(_ebpf_flush_timer);
    _ebpf_flush_timer = NULL;

    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        // Release all memory that is still in the free list.
        _ebpf_epoch_release_free_list(&_ebpf_epoch_cpu_table[cpu_id], MAXINT64);
        ebpf_assert(ebpf_list_is_empty(&_ebpf_epoch_cpu_table[cpu_id].free_list));
        ebpf_lock_destroy(&_ebpf_epoch_cpu_table[cpu_id].lock);
        ebpf_hash_table_destroy(_ebpf_epoch_cpu_table[cpu_id].thread_table);
        _ebpf_epoch_cpu_table[cpu_id].thread_table = NULL;
        ebpf_free_non_preemptible_work_item(_ebpf_epoch_cpu_table[cpu_id].stale_worker);
    }
    _ebpf_epoch_cpu_count = 0;

    ebpf_free_cache_aligned(_ebpf_epoch_cpu_table);
    EBPF_RETURN_VOID();
}

ebpf_result_t
ebpf_epoch_enter()
{
    ebpf_result_t return_value;
    uint32_t current_cpu;
    ebpf_epoch_state_t* epoch_state = NULL;
    // Capture preemptible state outside lock
    bool is_preemptible = ebpf_is_preemptible();
    uintptr_t old_thread_affinity = 0;
    current_cpu = ebpf_get_current_cpu();

    // If the current CPU is not in the CPU table, then fail the enter.
    if (current_cpu >= _ebpf_epoch_cpu_count) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    // Set the thread affinity to the current CPU.
    if (is_preemptible) {
        return_value = ebpf_set_current_thread_affinity((uintptr_t)1 << current_cpu, &old_thread_affinity);
        if (return_value != EBPF_SUCCESS) {
            return EBPF_OPERATION_NOT_SUPPORTED;
        }
    }

    // Grab the CPU lock.
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);

    // If this thread is preemptible, then find or create the per thread epoch state.
    if (is_preemptible) {
        // Find or create the thread entry.
        ebpf_epoch_thread_entry_t* thread_entry = _ebpf_epoch_get_thread_entry(
            current_cpu, ebpf_get_current_thread_id(), EBPF_EPOCH_GET_THREAD_ENTRY_OPTION_CREATE_IF_NOT_FOUND);
        if (!thread_entry) {
            return_value = EBPF_NO_MEMORY;
            goto Done;
        }

        thread_entry->old_thread_affinity_mask = old_thread_affinity;

        // Update the thread entry's last used time.
        thread_entry->last_used_time = ebpf_query_time_since_boot(false);
        epoch_state = &thread_entry->epoch_state;
    } else {
        // Otherwise grab the per-CPU epoch state.
        epoch_state = &_ebpf_epoch_cpu_table[current_cpu].epoch_state;
    }

    // Capture the current epoch.
    epoch_state->epoch = _ebpf_current_epoch;

    // Mark the epoch state as active.
    epoch_state->active = true;
    return_value = EBPF_SUCCESS;

Done:
    // Release the CPU lock.
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, state);

    // Restore thread affinity on failure
    if (is_preemptible && return_value != 0) {
        ebpf_restore_current_thread_affinity(old_thread_affinity);
    }
    return return_value;
}

void
ebpf_epoch_exit()
{
    ebpf_epoch_state_t* epoch_state = NULL;
    // Capture preemptible state outside lock
    bool is_preemptible = ebpf_is_preemptible();
    uint32_t current_cpu = ebpf_get_current_cpu();
    uintptr_t old_thread_affinity = 0;

    bool release_free_list = false;
    if (current_cpu >= _ebpf_epoch_cpu_count) {
        return;
    }

    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);

    // If this thread is preemptible, then find the per thread epoch state.
    if (is_preemptible) {
        // Get the thread entry for the current thread.
        ebpf_epoch_thread_entry_t* thread_entry = _ebpf_epoch_get_thread_entry(
            current_cpu, ebpf_get_current_thread_id(), EBPF_EPOCH_GET_THREAD_ENTRY_OPTION_DO_NOT_CREATE);

        // If the thread entry is not found, then exit.
        ebpf_assert(thread_entry);
        if (!thread_entry) {
            goto Done;
        }

        // Update the thread entry's last used time.
        thread_entry->last_used_time = ebpf_query_time_since_boot(false);

        old_thread_affinity = thread_entry->old_thread_affinity_mask;
        epoch_state = &thread_entry->epoch_state;
    } else {
        // Otherwise grab the per-CPU epoch state.
        epoch_state = &_ebpf_epoch_cpu_table[current_cpu].epoch_state;
    }

    // Capture the current epoch.
    epoch_state->epoch = _ebpf_current_epoch;
    // Mark the epoch state as inactive.
    epoch_state->active = false;
    // Mark the epoch state as not stale.
    epoch_state->stale = false;

    if (!ebpf_list_is_empty(&_ebpf_epoch_cpu_table[current_cpu].free_list)) {
        release_free_list = true;
    }

Done:
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, state);
    if (release_free_list) {
        _ebpf_epoch_release_free_list(&_ebpf_epoch_cpu_table[current_cpu], _ebpf_release_epoch);
    }

    if (is_preemptible) {
        // Restore the thread's affinity mask.
        ebpf_restore_current_thread_affinity(old_thread_affinity);
    }
}

void
ebpf_epoch_flush()
{
    int64_t released_epoch;
    ebpf_result_t return_value = _ebpf_epoch_get_release_epoch(&released_epoch);
    if (return_value == EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_EPOCH, "_ebpf_release_epoch updated", released_epoch);
        // _ebpf_release_epoch is updated outside of any lock.
        _ebpf_release_epoch = released_epoch;
    }
}

void*
ebpf_epoch_allocate(size_t size)
{
    ebpf_assert(size);
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

    // If eBPF is terminating then free immediately.
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

    // If eBPF is terminating then execute immediately.
    if (_ebpf_epoch_rundown) {
        work_item->callback(work_item->callback_context);
        return;
    }

    // Items are inserted into the free list in increasing epoch order.
    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);
    work_item->header.freed_epoch = ebpf_interlocked_increment_int64(&_ebpf_current_epoch) - 1;
    ebpf_list_insert_tail(&_ebpf_epoch_cpu_table[current_cpu].free_list, &work_item->header.list_entry);
    _ebpf_epoch_arm_timer_if_needed(&_ebpf_epoch_cpu_table[current_cpu]);
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

bool
ebpf_epoch_is_free_list_empty(uint32_t cpu_id)
{
    bool is_free_list_empty = false;
    ebpf_lock_state_t lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].lock);
    is_free_list_empty = ebpf_list_is_empty(&_ebpf_epoch_cpu_table[cpu_id].free_list);
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[cpu_id].lock, lock_state);
    return is_free_list_empty;
}

static void
_ebpf_epoch_release_free_list(_In_ ebpf_epoch_cpu_entry_t* cpu_entry, int64_t released_epoch)
{
    ebpf_lock_state_t lock_state;
    ebpf_list_entry_t* entry;
    ebpf_epoch_allocation_header_t* header;
    ebpf_list_entry_t free_list;

    ebpf_list_initialize(&free_list);

    lock_state = ebpf_lock_lock(&cpu_entry->lock);

    // Move all expired items to the free list.
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

    // Arm the timer if needed.
    _ebpf_epoch_arm_timer_if_needed(cpu_entry);

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
    uint64_t now = ebpf_query_time_since_boot(false);
    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_EPOCH,
        "Captured value of _ebpf_current_epoch",
        lowest_epoch);

    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_epoch_thread_entry_t* thread_entry = NULL;
        uintptr_t thread_id = 0;

        // Grab the CPU epoch lock.
        lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].lock);

        // Clear the flush timer flag and re-arm the timer if needed.
        _ebpf_epoch_cpu_table[cpu_id].epoch_state.timer_armed = false;
        _ebpf_epoch_arm_timer_if_needed(&_ebpf_epoch_cpu_table[cpu_id]);

        // Check for stale items in the free list.
        if (!ebpf_list_is_empty(&_ebpf_epoch_cpu_table[cpu_id].free_list)) {
            // If the stale flag is set, then schedule the DPC to release the stale items.
            if (_ebpf_epoch_cpu_table[cpu_id].epoch_state.stale) {
                if (!_ebpf_epoch_cpu_table[cpu_id].stale_worker) {
                    ebpf_allocate_non_preemptible_work_item(
                        &_ebpf_epoch_cpu_table[cpu_id].stale_worker, cpu_id, _ebpf_epoch_stale_worker, NULL);
                }
                if (_ebpf_epoch_cpu_table[cpu_id].stale_worker) {
                    ebpf_queue_non_preemptible_work_item(_ebpf_epoch_cpu_table[cpu_id].stale_worker, NULL);
                }
            } else {
                _ebpf_epoch_cpu_table[cpu_id].epoch_state.stale = true;
            }
        }

        // Include this epoch state if it's active.
        if (_ebpf_epoch_cpu_table[cpu_id].epoch_state.active) {
            lowest_epoch = min(lowest_epoch, _ebpf_epoch_cpu_table[cpu_id].epoch_state.epoch);
        }

        // Loop over all the threads in this CPU entry.
        do {
            // Get the next per-thread entry from this CPU.
            return_value = ebpf_hash_table_next_key_and_value(
                _ebpf_epoch_cpu_table[cpu_id].thread_table,
                thread_id == 0 ? NULL : (uint8_t*)&thread_id,
                (uint8_t*)&thread_id,
                (uint8_t**)&thread_entry);

            // There are no more entries in the table.
            if (return_value != EBPF_SUCCESS) {
                break;
            }

            // Include this epoch state if it's active.
            if (thread_entry->epoch_state.active) {
                int64_t age = now - thread_entry->last_used_time;
                if (age > EBPF_EPOCH_STALE_THREAD_TIME_IN_NANO_SECONDS) {
                    EBPF_LOG_MESSAGE_UINT64_UINT64(
                        EBPF_TRACELOG_LEVEL_VERBOSE,
                        EBPF_TRACELOG_KEYWORD_EPOCH,
                        "Stale active thread entry",
                        (uint64_t)thread_id,
                        age);
                    // Reset last_used_time time to limit rate of logging.
                    thread_entry->last_used_time = now;
                }
                lowest_epoch = min(lowest_epoch, thread_entry->epoch_state.epoch);
            }
        } while (return_value == EBPF_SUCCESS);

        // Release the CPU epoch lock.
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

static void
_ebpf_flush_worker(_In_ void* context)
{
    UNREFERENCED_PARAMETER(context);

    ebpf_epoch_flush();
}

static _Requires_lock_held_(_ebpf_epoch_cpu_table[cpu_id].lock) ebpf_epoch_thread_entry_t* _ebpf_epoch_get_thread_entry(
    uint32_t cpu_id, uintptr_t thread_id, ebpf_epoch_get_thread_entry_option_t option)
{
    ebpf_result_t return_value;
    ebpf_epoch_thread_entry_t* thread_entry = NULL;
    ebpf_epoch_thread_entry_t local_thread_epoch = {MAXINT64};

    return_value = ebpf_hash_table_find(
        _ebpf_epoch_cpu_table[cpu_id].thread_table, (uint8_t*)&thread_id, (uint8_t**)&thread_entry);
    if (return_value == EBPF_KEY_NOT_FOUND && (option == EBPF_EPOCH_GET_THREAD_ENTRY_OPTION_CREATE_IF_NOT_FOUND)) {
        return_value = ebpf_hash_table_update(
            _ebpf_epoch_cpu_table[cpu_id].thread_table,
            (const uint8_t*)&thread_id,
            (const uint8_t*)&local_thread_epoch,
            EBPF_HASH_TABLE_OPERATION_INSERT);
        ebpf_hash_table_find(
            _ebpf_epoch_cpu_table[cpu_id].thread_table, (uint8_t*)&thread_id, (uint8_t**)&thread_entry);
    }

    return thread_entry;
}

static _Requires_lock_held_(cpu_entry->lock) void _ebpf_epoch_arm_timer_if_needed(ebpf_epoch_cpu_entry_t* cpu_entry)
{
    if (cpu_entry->epoch_state.timer_disabled) {
        return;
    }
    if (cpu_entry->epoch_state.timer_armed) {
        return;
    }
    if (ebpf_list_is_empty(&cpu_entry->free_list)) {
        return;
    }
    cpu_entry->epoch_state.timer_armed = true;
    ebpf_schedule_timer_work_item(_ebpf_flush_timer, EBPF_EPOCH_FLUSH_DELAY_IN_MICROSECONDS);
    return;
}

static void
_ebpf_epoch_stale_worker(_In_ void* work_item_context, _In_ void* parameter_1)
{
    UNREFERENCED_PARAMETER(work_item_context);
    UNREFERENCED_PARAMETER(parameter_1);
    ebpf_epoch_enter();
    ebpf_epoch_exit();
}
