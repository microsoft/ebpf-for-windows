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
// If the thread is preemptible, it blocks waiting for the semaphore (to ensure that the thread entry table has an
// available entry). If the thread is not preemptible, it is guaranteed that the thread entry table has an available
// entry. The thread entry table is a fixed size hash table based on the thread ID. The current epoch is read and stored
// in the thread entry table.
//
// ebpf_epoch_exit:
// First:
// The entry is set to zero to mark it as freed.
//
// Second:
// Any entries in the per CPU free-list with epoch older than _ebpf_release_epoch are freed.
//
// Third:
// If the free-list still contains entries, the _ebpf_flush_timer is set (if not already set).
//
// Fourth:
// If the thread is preemptible the semaphore is released.
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
// The thread entry table is a fixed size per-CPU hash table for tracking per-thread ebpf_epoch_state_t. The hash is
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

typedef struct _ebpf_epoch_state
{
    int64_t epoch; // The highest epoch seen by this epoch state.
} ebpf_epoch_state_t;

#define EBPF_EPOCH_THREAD_TABLE_SIZE \
    (EBPF_CACHE_LINE_SIZE / sizeof(ebpf_epoch_state_t)) // Number of entries in the thread table.

// Number of reserved entries in the thread table.
// One for the current thread running at DISPATCH_LEVEL.
#define EBPF_EPOCH_THREAD_TABLE_RESERVED_COUNT 1

// Table to track per CPU state.
// This table must fit into a multiple of EBPF_CACHE_LINE_SIZE.
#pragma warning(disable : 4324) // Structure was padded due to alignment specifier.
typedef __declspec(align(EBPF_CACHE_LINE_SIZE)) struct _ebpf_epoch_cpu_entry
{
    _Guarded_by_(lock) ebpf_epoch_state_t
        epoch_table[EBPF_EPOCH_THREAD_TABLE_SIZE]; // Epochs on this CPU. If zero, then it is not active.
    ebpf_lock_t lock;
    ebpf_semaphore_t* epoch_table_semaphore; // Semaphore to number of threads active in the epoch per CPU.
    _Guarded_by_(lock) ebpf_non_preemptible_work_item_t* stale_worker; // Per-CPU stale worker DPC.
    _Guarded_by_(lock) ebpf_list_entry_t free_list;                    // Per-CPU free list.
    _Guarded_by_(lock) int timer_armed : 1;
    _Guarded_by_(lock) int stale : 1;
    _Guarded_by_(lock) int rundown_in_progress : 1;
} ebpf_epoch_cpu_entry_t;

C_ASSERT(sizeof(ebpf_epoch_cpu_entry_t) % EBPF_CACHE_LINE_SIZE == 0);            // Verify alignment.
C_ASSERT(EBPF_EPOCH_THREAD_TABLE_SIZE > EBPF_EPOCH_THREAD_TABLE_RESERVED_COUNT); // Verify that the reserved count fits.

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
    ebpf_preemptible_work_item_t* preemptible_work_item;
    void* callback_context;
    const void (*callback)(_Inout_ void* context);
} ebpf_epoch_work_item_t;

EX_RUNDOWN_REF _ebpf_epoch_work_item_rundown_ref;

/**
 * @brief Hash a thread ID into an 8bit number.
 *
 * @param[in] thread_id Thread ID to hash.
 * @return 8bit bucket key.
 */
static size_t
_ebpf_epoch_hash_thread_id(uintptr_t thread_id);

/**
 * @brief Find the next available epoch state entry in the per-CPU table.
 * @param[in] cpu_entry Per-CPU entry to search.
 * @return Pointer to the next available epoch entry.
 */
_Requires_lock_held_(cpu_entry->lock) static ebpf_epoch_state_t* _ebpf_epoch_next_available_epoch_entry(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry);

/**
 * @brief Get the CPU ID from the epoch state.
 *
 * @param[in] epoch_state The epoch state to get the CPU ID from.
 * @return The CPU ID.
 */
uint32_t
_ebpf_epoch_get_cpu_id_from_state(_In_ ebpf_epoch_state_t* epoch_state);

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

static void
_ebpf_epoch_work_item_callback(void* context)
{
    ebpf_epoch_work_item_t* work_item = (ebpf_epoch_work_item_t*)context;
    work_item->callback(work_item->callback_context);
    work_item->preemptible_work_item = NULL;
    ExReleaseRundownProtection(&_ebpf_epoch_work_item_rundown_ref);

    // Caller of this function calls ebpf_free_preemptible_work_item.
}

_Must_inspect_result_ ebpf_result_t
ebpf_epoch_initiate()
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value = EBPF_SUCCESS;
    uint32_t cpu_id;
    uint32_t cpu_count;

    cpu_count = ebpf_get_cpu_count();

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
        ebpf_lock_create(&cpu_entry->lock);
        ebpf_list_initialize(&cpu_entry->free_list);
    }

    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[cpu_id];
        return_value = ebpf_semaphore_create(
            &cpu_entry->epoch_table_semaphore,
            EBPF_EPOCH_THREAD_TABLE_SIZE - EBPF_EPOCH_THREAD_TABLE_RESERVED_COUNT,
            EBPF_EPOCH_THREAD_TABLE_SIZE - EBPF_EPOCH_THREAD_TABLE_RESERVED_COUNT);
        if (return_value != EBPF_SUCCESS) {
            goto Error;
        }
    }

    return_value = ebpf_allocate_timer_work_item(&_ebpf_flush_timer, _ebpf_flush_worker, NULL);
    if (return_value != EBPF_SUCCESS) {
        goto Error;
    }

    ExInitializeRundownProtection(&_ebpf_epoch_work_item_rundown_ref);

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

    if (!_ebpf_epoch_cpu_table) {
        return;
    }

    // First disable all timers.
    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_lock_state_t lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].lock);
        _ebpf_epoch_cpu_table[cpu_id].rundown_in_progress = true;
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
        ebpf_semaphore_destroy(_ebpf_epoch_cpu_table[cpu_id].epoch_table_semaphore);
    }

    // Wait for all work items to complete.
    ExWaitForRundownProtectionRelease(&_ebpf_epoch_work_item_rundown_ref);

    _ebpf_epoch_cpu_count = 0;

    ebpf_free_cache_aligned(_ebpf_epoch_cpu_table);
    _ebpf_epoch_cpu_table = NULL;
    EBPF_RETURN_VOID();
}

ebpf_epoch_state_t*
ebpf_epoch_enter()
{
    uint32_t current_cpu;
    ebpf_epoch_state_t* epoch_entry = NULL;
    // Capture preemptible state outside lock
    bool is_preemptible = ebpf_is_preemptible();
    current_cpu = ebpf_get_current_cpu();

    if (is_preemptible) {
        // Prevent APCs from running.
        ebpf_enter_critical_region();

        // Block until a thread entry is available.
        ebpf_semaphore_wait(_ebpf_epoch_cpu_table[current_cpu].epoch_table_semaphore);
        // After the semaphore is acquired, then there is at least 1 available epoch entry.
    }

    // If the current thread is not preemptible, then there is at least 1 available epoch entry.

    // Grab the CPU lock.
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);

    // Get the next available epoch entry.
    epoch_entry = _ebpf_epoch_next_available_epoch_entry(&_ebpf_epoch_cpu_table[current_cpu]);
    ebpf_assert(epoch_entry != NULL);
    _Analysis_assume_(epoch_entry != NULL);
    ebpf_assert(epoch_entry->epoch == 0);

    // Capture the current epoch.
    epoch_entry->epoch = _ebpf_current_epoch;

    // Release the CPU lock.
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, state);
    return epoch_entry;
}

void
ebpf_epoch_exit(_In_ ebpf_epoch_state_t* epoch_state)
{
    uint32_t current_cpu = _ebpf_epoch_get_cpu_id_from_state(epoch_state);
    // Capture preemptible state outside lock
    bool is_preemptible = ebpf_is_preemptible();
    bool release_free_list = false;

    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);

    // Mark the epoch state as available.
    ebpf_assert(epoch_state->epoch != 0);
    epoch_state->epoch = 0;

    // Mark the epoch state as not stale.
    _ebpf_epoch_cpu_table[current_cpu].stale = false;

    if (!ebpf_list_is_empty(&_ebpf_epoch_cpu_table[current_cpu].free_list)) {
        release_free_list = true;
    }

    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, state);
    if (release_free_list) {
        _ebpf_epoch_release_free_list(&_ebpf_epoch_cpu_table[current_cpu], _ebpf_release_epoch);
    }

    if (is_preemptible) {
        // Release the thread entry.
        ebpf_semaphore_release(_ebpf_epoch_cpu_table[current_cpu].epoch_table_semaphore);

        // Allow APCs to run.
        ebpf_leave_critical_region();
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
    if (header) {
        header++;
    }

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

    if (!memory) {
        return;
    }

    header--;

    ebpf_assert(header->freed_epoch == 0);
    header->entry_type = EBPF_EPOCH_ALLOCATION_MEMORY;

    // Items are inserted into the free list in increasing epoch order.
    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);
    if (!_ebpf_epoch_cpu_table[current_cpu].rundown_in_progress) {
        header->freed_epoch = ebpf_interlocked_increment_int64(&_ebpf_current_epoch) - 1;
        ebpf_list_insert_tail(&_ebpf_epoch_cpu_table[current_cpu].free_list, &header->list_entry);
    } else {
        ebpf_free(header);
    }
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

    if (!ExAcquireRundownProtection(&_ebpf_epoch_work_item_rundown_ref)) {
        ebpf_free(work_item);
        return NULL;
    }

    ebpf_result_t result = ebpf_allocate_preemptible_work_item(
        &work_item->preemptible_work_item, _ebpf_epoch_work_item_callback, work_item);
    if (result != EBPF_SUCCESS) {
        ExReleaseRundownProtection(&_ebpf_epoch_work_item_rundown_ref);
        ebpf_free(work_item);
        return NULL;
    }

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

    // Items are inserted into the free list in increasing epoch order.
    lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[current_cpu].lock);
    if (!_ebpf_epoch_cpu_table[current_cpu].rundown_in_progress) {
        // If rundown is not in progress, then the work item is inserted into the free list.
        work_item->header.freed_epoch = ebpf_interlocked_increment_int64(&_ebpf_current_epoch) - 1;
        ebpf_list_insert_tail(&_ebpf_epoch_cpu_table[current_cpu].free_list, &work_item->header.list_entry);
        _ebpf_epoch_arm_timer_if_needed(&_ebpf_epoch_cpu_table[current_cpu]);
    } else {
        // If rundown is in progress, then the work item is executed immediately.
        ebpf_queue_preemptible_work_item(work_item->preemptible_work_item);
    }
    ebpf_lock_unlock(&_ebpf_epoch_cpu_table[current_cpu].lock, lock_state);
}

void
ebpf_epoch_cancel_work_item(_Inout_ ebpf_epoch_work_item_t* work_item)
{
    uint32_t current_cpu;
    current_cpu = ebpf_get_current_cpu();
    if (current_cpu >= _ebpf_epoch_cpu_count) {
        return;
    }
    if (!work_item) {
        return;
    }

    ebpf_assert(work_item->header.list_entry.Flink == NULL);

    // ebpf_free_preemptible_work_item() frees both the work item and the preemptible work item.
    ebpf_free_preemptible_work_item(work_item->preemptible_work_item);

    ExReleaseRundownProtection(&_ebpf_epoch_work_item_rundown_ref);
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
            ebpf_queue_preemptible_work_item(work_item->preemptible_work_item);
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
        // Grab the CPU epoch lock.
        lock_state = ebpf_lock_lock(&_ebpf_epoch_cpu_table[cpu_id].lock);

        // Clear the flush timer flag and re-arm the timer if needed.
        _ebpf_epoch_cpu_table[cpu_id].timer_armed = false;
        _ebpf_epoch_arm_timer_if_needed(&_ebpf_epoch_cpu_table[cpu_id]);

        // Check for stale items in the free list.
        if (!ebpf_list_is_empty(&_ebpf_epoch_cpu_table[cpu_id].free_list)) {
            // If the stale flag is set, then schedule the DPC to release the stale items.
            if (_ebpf_epoch_cpu_table[cpu_id].stale) {
                if (!_ebpf_epoch_cpu_table[cpu_id].stale_worker) {
                    // If ebpf_allocate_non_preemptible_work_item fails, it will retry next time the timer fires.
                    (void)ebpf_allocate_non_preemptible_work_item(
                        &_ebpf_epoch_cpu_table[cpu_id].stale_worker, cpu_id, _ebpf_epoch_stale_worker, NULL);
                }
                if (_ebpf_epoch_cpu_table[cpu_id].stale_worker) {
                    ebpf_queue_non_preemptible_work_item(_ebpf_epoch_cpu_table[cpu_id].stale_worker, NULL);
                }
            } else {
                _ebpf_epoch_cpu_table[cpu_id].stale = true;
            }
        }

        // Loop over the thread table and compute the lowest active epoch.
        for (size_t index = 0; index < EBPF_EPOCH_THREAD_TABLE_SIZE; index++) {
            ebpf_epoch_state_t* epoch_state = &_ebpf_epoch_cpu_table[cpu_id].epoch_table[index];
            if (epoch_state->epoch != 0) {
                lowest_epoch = min(lowest_epoch, epoch_state->epoch);
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
    if (cpu_entry->rundown_in_progress) {
        return;
    }
    if (cpu_entry->timer_armed) {
        return;
    }
    if (ebpf_list_is_empty(&cpu_entry->free_list)) {
        return;
    }
    cpu_entry->timer_armed = true;
    ebpf_schedule_timer_work_item(_ebpf_flush_timer, EBPF_EPOCH_FLUSH_DELAY_IN_MICROSECONDS);
    return;
}

static void
_ebpf_epoch_stale_worker(_In_ const void* work_item_context, _In_ const void* parameter_1)
{
    UNREFERENCED_PARAMETER(work_item_context);
    UNREFERENCED_PARAMETER(parameter_1);
    ebpf_epoch_exit(ebpf_epoch_enter());
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

_Requires_lock_held_(cpu_entry->lock) static ebpf_epoch_state_t* _ebpf_epoch_next_available_epoch_entry(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry)
{
    uintptr_t thread_id = ebpf_get_current_thread_id();
    // Find the ideal bucket for this thread_id.
    size_t bucket = _ebpf_epoch_hash_thread_id(thread_id) % EBPF_EPOCH_THREAD_TABLE_SIZE;
    // Search for the thread_id in the table starting at the ideal bucket.
    for (size_t i = 0; i < EBPF_EPOCH_THREAD_TABLE_SIZE; i++) {
        ebpf_epoch_state_t* epoch_state = &cpu_entry->epoch_table[bucket];
        if (epoch_state->epoch == 0) {
            return epoch_state;
        }
        bucket = (bucket + 1) % EBPF_EPOCH_THREAD_TABLE_SIZE;
    }
    ebpf_assert(!"Epoch state not found");
    return NULL;
}

uint32_t
_ebpf_epoch_get_cpu_id_from_state(_In_ ebpf_epoch_state_t* state)
{
    uintptr_t offset = (uintptr_t)state;
    offset -= (uintptr_t)_ebpf_epoch_cpu_table;
    offset /= sizeof(ebpf_epoch_cpu_entry_t);
    return (uint32_t)offset;
}