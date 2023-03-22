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
//
// Thread entry table:
// The thread entry is a fixed size per-CPU hash table for tracking per-thread ebpf_epoch_state_t. The hash is
// based on the thread ID. The thread entry table is protected by a semaphore that limits the number of threads
// that can be active in the epoch at any one time. If a thread attempts to enter the epoch and the semaphore
// count is 0, then the thread blocks until a thread exits the epoch, which ensures that the thread entry table
// has an available entry for the thread to use.

// Delay after the _ebpf_flush_timer is set before it runs.
#define EBPF_EPOCH_FLUSH_DELAY_IN_MICROSECONDS 1000

// Time before logging that a thread entry is stale
#define EBPF_EPOCH_STALE_THREAD_TIME_IN_NANO_SECONDS 10000000000 // 10 seconds

// The maximum time a thread remains in the thread table while inactive.
#define EBPF_EPOCH_THREAD_TABLE_TIMEOUT_IN_NANO_SECONDS 1000000000 // 1 second

#define EBPF_NANO_SECONDS_PER_FILETIME_TICK 100

#define EBPF_EPOCH_RESERVED_THREAD_ENTRY_COUNT 1

typedef struct _ebpf_epoch_state
{
    int64_t epoch;           // The highest epoch seen by this epoch state.
    bool active : 1;         // Currently within an entry/exit block.
    bool timer_armed : 1;    // This state has requested the global timer.
    bool stale : 1;          // This state has entries that haven't been freed.
    bool timer_disabled : 1; // Prevent re-arming the timer during shutdown.
} ebpf_epoch_state_t;

typedef struct _ebpf_epoch_thread_entry
{
    ebpf_epoch_state_t epoch_state;     // Per-thread epoch state.
    uintptr_t old_thread_affinity_mask; // Thread affinity mask before entering an entry/exit block.
    uintptr_t thread_id;                // Thread ID of the thread that owns this entry or 0 if unused.
} ebpf_epoch_thread_entry_t;

// The epoch code limits the number of threads that can be active at any one time per CPU.
// If additional threads attempt to call ebpf_epoch_enter, they will block until a thread exits the epoch.
#define EBPF_EPOCH_THREAD_ENTRY_TABLE_SIZE ((EBPF_CACHE_LINE_SIZE * 3) / sizeof(ebpf_epoch_thread_entry_t))

// Table to track per CPU state.
// This table must fit into a multiple of EBPF_CACHE_LINE_SIZE.
#pragma warning(disable : 4324) // Structure was padded due to alignment specifier.
typedef __declspec(align(EBPF_CACHE_LINE_SIZE)) struct _ebpf_epoch_cpu_entry
{
    ebpf_lock_t lock;
    _Guarded_by_(lock) ebpf_epoch_state_t epoch_state;                 // Per-CPU epoch state.
    _Guarded_by_(lock) ebpf_list_entry_t free_list;                    // Per-CPU free list.
    _Guarded_by_(lock) ebpf_non_preemptible_work_item_t* stale_worker; // Per-CPU stale worker DPC.
    ebpf_semaphore_t* thread_entry_table_semaphore; // Semaphore to number of threads active in the epoch per CPU.
    _Guarded_by_(lock)
        ebpf_epoch_thread_entry_t thread_entry_table[EBPF_EPOCH_THREAD_ENTRY_TABLE_SIZE]; // Per-thread epoch state.
} ebpf_epoch_cpu_entry_t;

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
    const void (*callback)(_Inout_ void* context);
} ebpf_epoch_work_item_t;

/**
 * @brief Hash a thread ID into an 8bit number.
 *
 * @param[in] thread_id Thread ID to hash.
 * @return 8bit bucket key.
 */
static size_t
_ebpf_epoch_hash_thread_id(uintptr_t thread_id);

/**
 * @brief Get the thread entry for the current thread or find the first unused entry. Uses the thread ID as a hash key
 * and searches the thread entry table for a matching entry starting at the hash key. Unused entries are found by
 * searching the table for an entry with a thread ID of 0.
 *
 * @param[in,out] thread_id Thread ID to find or 0 to find the first unused entry.
 * @return Pointer to the thread entry to use.
 */
_Requires_lock_held_(cpu_entry->lock) static ebpf_epoch_thread_entry_t* _ebpf_epoch_get_thread_entry(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, uintptr_t thread_id);

/**
 * @brief Remove all entries from the per-CPU free list that have an epoch that is before released_epoch.
 *
 * @param[in] cpu_id The per-CPU free list to search.
 * @param[in] released_epoch The epoch to release.
 */
static void
_ebpf_epoch_release_free_list(_Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, int64_t released_epoch);

/**
 * @brief Determine the newest inactive epoch and return it.
 *
 * @param[out] release_epoch The newest inactive epoch.
 */
static void
_ebpf_epoch_get_release_epoch(_Out_ int64_t* released_epoch);

/**
 * @brief Routine executed on a timer to compute the newest inactive epoch.
 *
 * @param[in] context Unused.
 */
static void
_ebpf_flush_worker(_In_ const void* context);

/**
 * @brief Flush any stale entries from the per-CPU free list.
 *
 * @param[in] work_item_context Unused.
 * @param[in] parameter_1 Unused.
 */
static void
_ebpf_epoch_stale_worker(_In_ const void* work_item_context, _In_ const void* parameter_1);

/**
 * @brief Arm the flush timer if:
 *  Timer is not already armed.
 *  Timer is not disabled.
 *  Free list is not empty.
 */
static _Requires_lock_held_(cpu_entry->lock) void _ebpf_epoch_arm_timer_if_needed(ebpf_epoch_cpu_entry_t* cpu_entry);

_Must_inspect_result_ ebpf_result_t
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

    _ebpf_epoch_cpu_table = ebpf_allocate_cache_aligned_with_tag(
        sizeof(ebpf_epoch_cpu_entry_t) * _ebpf_epoch_cpu_count, EBPF_POOL_TAG_EPOCH);
    if (!_ebpf_epoch_cpu_table) {
        return_value = EBPF_NO_MEMORY;
        goto Error;
    }

    ebpf_assert(EBPF_CACHE_ALIGN_POINTER(_ebpf_epoch_cpu_table) == _ebpf_epoch_cpu_table);

    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[cpu_id];
        cpu_entry->epoch_state.epoch = _ebpf_current_epoch;
        cpu_entry->epoch_state.active = false;
        ebpf_lock_create(&cpu_entry->lock);

        ebpf_list_initialize(&cpu_entry->free_list);
    }

    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[cpu_id];
        return_value = ebpf_semaphore_create(
            &cpu_entry->thread_entry_table_semaphore,
            EBPF_EPOCH_THREAD_ENTRY_TABLE_SIZE,
            EBPF_EPOCH_THREAD_ENTRY_TABLE_SIZE);
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

    if (!_ebpf_epoch_cpu_table) {
        return;
    }

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
        ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[cpu_id];
        // Release all memory that is still in the free list.
        _ebpf_epoch_release_free_list(cpu_entry, MAXINT64);
        ebpf_assert(ebpf_list_is_empty(&cpu_entry->free_list));
#pragma warning(suppress : 6001) // _ebpf_epoch_cpu_table is initalized.
        ebpf_lock_destroy(&_ebpf_epoch_cpu_table[cpu_id].lock);
#pragma warning(suppress : 6001) // _ebpf_epoch_cpu_table is initalized.
        ebpf_free_non_preemptible_work_item(_ebpf_epoch_cpu_table[cpu_id].stale_worker);
#pragma warning(suppress : 6001) // _ebpf_epoch_cpu_table is initalized.
        ebpf_semaphore_destroy(_ebpf_epoch_cpu_table[cpu_id].thread_entry_table_semaphore);
    }
    _ebpf_epoch_cpu_count = 0;

    ebpf_free_cache_aligned(_ebpf_epoch_cpu_table);
    _ebpf_epoch_cpu_table = NULL;
    EBPF_RETURN_VOID();
}

void
ebpf_epoch_enter()
{
    uint32_t current_cpu;
    ebpf_epoch_state_t* epoch_state = NULL;
    // Capture preemptible state outside lock
    bool is_preemptible = ebpf_is_preemptible();
    uintptr_t old_thread_affinity = 0;
    current_cpu = ebpf_get_current_cpu();

    // Set the thread affinity to the current CPU.
    if (is_preemptible) {
        ebpf_assert_success(ebpf_set_current_thread_affinity((uintptr_t)1 << current_cpu, &old_thread_affinity));

        // Block until a thread entry is available.
        ebpf_semaphore_wait(_ebpf_epoch_cpu_table[current_cpu].thread_entry_table_semaphore);
        // After the semaphore is acquired, then there is at least 1 available thread entry.
    }

    // Grab the CPU lock.
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);

    // If this thread is preemptible, then find or create the per thread epoch state.
    if (is_preemptible) {
        // Find the first available thread entry.
        ebpf_epoch_thread_entry_t* thread_entry = _ebpf_epoch_get_thread_entry(&_ebpf_epoch_cpu_table[current_cpu], 0);
        ebpf_assert(thread_entry != NULL);
        ebpf_assert(thread_entry->thread_id == 0);

        // Mark thread entry as in use.
        thread_entry->thread_id = ebpf_get_current_thread_id();
        thread_entry->old_thread_affinity_mask = old_thread_affinity;

        // Update the thread entry's last used time.
        epoch_state = &thread_entry->epoch_state;
    } else {
        // Otherwise grab the per-CPU epoch state.
        epoch_state = &_ebpf_epoch_cpu_table[current_cpu].epoch_state;
    }

    // Capture the current epoch.
    epoch_state->epoch = _ebpf_current_epoch;

    ebpf_assert(!epoch_state->active);
    // Mark the epoch state as active.
    epoch_state->active = true;

    // Release the CPU lock.
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, state);
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

    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);

    // If this thread is preemptible, then find the per thread epoch state.
    if (is_preemptible) {
        // Get the thread entry for the current thread.
        uintptr_t thread_id = ebpf_get_current_thread_id();
        ebpf_epoch_thread_entry_t* thread_entry =
            _ebpf_epoch_get_thread_entry(&_ebpf_epoch_cpu_table[current_cpu], thread_id);

        // Having a thread entry is a precondition for calling ebpf_epoch_exit().
        ebpf_assert(thread_entry != NULL);
        ebpf_assert(thread_entry->thread_id == thread_id);

        // Mark thread entry as free.
        thread_entry->thread_id = 0;

        old_thread_affinity = thread_entry->old_thread_affinity_mask;
        epoch_state = &thread_entry->epoch_state;
    } else {
        // Otherwise grab the per-CPU epoch state.
        epoch_state = &_ebpf_epoch_cpu_table[current_cpu].epoch_state;
    }

    // Capture the current epoch.
    epoch_state->epoch = _ebpf_current_epoch;
    ebpf_assert(epoch_state->active);
    // Mark the epoch state as inactive.
    epoch_state->active = false;
    // Mark the epoch state as not stale.
    epoch_state->stale = false;

    if (!ebpf_list_is_empty(&_ebpf_epoch_cpu_table[current_cpu].free_list)) {
        release_free_list = true;
    }

    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, state);
    if (release_free_list) {
        _ebpf_epoch_release_free_list(&_ebpf_epoch_cpu_table[current_cpu], _ebpf_release_epoch);
    }

    if (is_preemptible) {
        // Restore the thread's affinity mask.
        ebpf_restore_current_thread_affinity(old_thread_affinity);
        ebpf_semaphore_release(_ebpf_epoch_cpu_table[current_cpu].thread_entry_table_semaphore);
    }
}

void
ebpf_epoch_flush()
{
    int64_t released_epoch;
    if (!_ebpf_epoch_cpu_table) {
        return;
    }

    _ebpf_epoch_get_release_epoch(&released_epoch);
    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_EPOCH, "_ebpf_release_epoch updated", released_epoch);
    // _ebpf_release_epoch is updated outside of any lock.
    _ebpf_release_epoch = released_epoch;
}

_Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_epoch_allocate_with_tag(size_t size, uint32_t tag)
{
    ebpf_assert(size);
    ebpf_epoch_allocation_header_t* header;

    size += sizeof(ebpf_epoch_allocation_header_t);
    header = (ebpf_epoch_allocation_header_t*)ebpf_allocate_with_tag(size, tag);
    if (header)
        header++;

    return header;
}

_Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_epoch_allocate(size_t size)
{
    return ebpf_epoch_allocate_with_tag(size, EBPF_POOL_TAG_EPOCH);
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
ebpf_epoch_allocate_work_item(_In_ void* callback_context, _In_ const void (*callback)(_Inout_ void* context))
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
ebpf_epoch_schedule_work_item(_Inout_ ebpf_epoch_work_item_t* work_item)
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
_ebpf_epoch_release_free_list(_Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, int64_t released_epoch)
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

static void
_ebpf_epoch_get_release_epoch(_Out_ int64_t* release_epoch)
{
    // Grab an non-authoritative version of _ebpf_current_epoch.
    // Note: If there are no active threads or non-preemptible work items then we need to assign
    // an epoch that is guaranteed to be older than any thread that starts after this point.
    // Grabbing the current epoch guarantees that, even if we have a stale value of _ebpf_current_epoch.
    int64_t lowest_epoch = _ebpf_current_epoch;
    uint32_t cpu_id;
    ebpf_lock_state_t lock_state;
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
                    // If ebpf_allocate_non_preemptible_work_item fails, it will retry next time the timer fires.
                    (void)ebpf_allocate_non_preemptible_work_item(
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

        // Loop over the thread table and compute the lowest active epoch.
        for (size_t index = 0; index < EBPF_EPOCH_THREAD_ENTRY_TABLE_SIZE; index++) {
            thread_entry = &_ebpf_epoch_cpu_table[cpu_id].thread_entry_table[index];
            thread_id = thread_entry->thread_id;
            if ((thread_id != 0) && (thread_entry->epoch_state.active)) {
                lowest_epoch = min(lowest_epoch, thread_entry->epoch_state.epoch);
            }
        }

        // Release the CPU epoch lock.
        ebpf_lock_unlock(&_ebpf_epoch_cpu_table[cpu_id].lock, lock_state);
    }

    *release_epoch = lowest_epoch - 1;
}

static void
_ebpf_flush_worker(_In_ const void* context)
{
    UNREFERENCED_PARAMETER(context);

    ebpf_epoch_flush();
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
_ebpf_epoch_stale_worker(_In_ const void* work_item_context, _In_ const void* parameter_1)
{
    UNREFERENCED_PARAMETER(work_item_context);
    UNREFERENCED_PARAMETER(parameter_1);
    ebpf_epoch_enter();
    ebpf_epoch_exit();
}

/**
 * @brief Hash a thread ID into an 8bit number.
 *
 * @param[in] thread_id Thread ID to hash.
 * @return 8bit bucket key.
 */
static size_t
_ebpf_epoch_hash_thread_id(uintptr_t thread_id)
{
    // Collapse top 32bits into lower 32bits.
    size_t v1 = (thread_id >> 32) ^ (thread_id & 0xFFFFFFFF);
    // Collapse top 16bits into lower 16bits.
    size_t v2 = (v1 >> 16) ^ (v1 & 0xFFFF);
    // Collapse top 8bits into lower 8bits and return it.
    return (v2 >> 8) ^ (v2 & 0xFF);
}

_Requires_lock_held_(cpu_entry->lock) static ebpf_epoch_thread_entry_t* _ebpf_epoch_get_thread_entry(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, uintptr_t thread_id)
{
    // Find the ideal bucket for this thread_id.
    size_t bucket = _ebpf_epoch_hash_thread_id(ebpf_get_current_thread_id()) % EBPF_EPOCH_THREAD_ENTRY_TABLE_SIZE;
    // Search for the thread_id in the table starting at the ideal bucket.
    for (size_t i = 0; i < EBPF_EPOCH_THREAD_ENTRY_TABLE_SIZE; i++) {
        ebpf_epoch_thread_entry_t* thread_entry = &cpu_entry->thread_entry_table[bucket];
        if (thread_entry->thread_id == thread_id) {
            return thread_entry;
        }
        bucket = (bucket + 1) % EBPF_EPOCH_THREAD_ENTRY_TABLE_SIZE;
    }
    ebpf_assert(!"Thread entry not found");
    return NULL;
}
