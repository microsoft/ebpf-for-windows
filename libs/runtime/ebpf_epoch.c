// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_tracelog.h"
#include "ebpf_work_queue.h"

/**
 * @brief Epoch Base Memory Reclamation.
 * Each thread that accesses memory that needs to be reclaimed is associated with an epoch via ebpf_epoch_enter() and
 * ebpf_epoch_exit().
 * Each CPU maintains a list of threads that are currently in an epoch. When a thread enters an epoch, it is added to
 * the per-CPU list. When a thread exits an epoch, it is removed from the per-CPU list and the CPU checks if the per-CPU
 * list is empty. If it is empty, then the CPU checks if the timer is armed. If the timer is not armed, then the CPU
 * arms the timer. When the timer expires, the release epoch computation is initiated. The release epoch computation is
 * a three-phase process.
 * 1) Each CPU determines the minimum epoch of all threads on the CPU.
 * 2) The minimum epoch is committed as the release epoch and any memory that is older than the release epoch is
 * released.
 * 3) The epoch_computation_in_progress flag is cleared which allows the epoch computation to be initiated  again.
 */

/**
 * @brief Delay after the _ebpf_flush_timer is set before it runs.
 */
#define EBPF_EPOCH_FLUSH_DELAY_IN_NANOSECONDS 1000000



#define EBPF_EPOCH_FAIL_FAST(REASON, ASSERTION) \
    if (!(ASSERTION)) {                         \
        ebpf_assert(!#ASSERTION);               \
        __fastfail(REASON);                     \
    }

#pragma warning(disable : 4324) // Structure was padded due to alignment specifier.
/**
 * @brief Per-CPU state.
 * Each entry is only accessed by the CPU that owns it and only at IRQL >= DISPATCH_LEVEL.
 * This ensures that no locks are required to access the per CPU state.
 */
typedef __declspec(align(EBPF_CACHE_LINE_SIZE)) struct _ebpf_epoch_cpu_entry
{
    LIST_ENTRY epoch_state_list;           ///< Per-CPU list of thread entries.
    ebpf_list_entry_t free_list;           ///< Per-CPU free list.
    int64_t current_epoch;                 ///< The current epoch for this CPU.
    int64_t released_epoch;                ///< The newest epoch that can be released.
    int timer_armed : 1;                   ///< Set if the flush timer is armed.
    int rundown_in_progress : 1;           ///< Set if rundown is in progress.
    int epoch_computation_in_progress : 1; ///< Set if epoch computation is in progress.
    ebpf_timed_work_queue_t* work_queue;   ///< Work queue used to schedule work items.
} ebpf_epoch_cpu_entry_t;

/**
 * @brief Table of per-CPU state.
 */
static _Writable_elements_(_ebpf_epoch_cpu_count) ebpf_epoch_cpu_entry_t* _ebpf_epoch_cpu_table = NULL;

/**
 * @brief Number of CPUs in the system as determined at initialization time.
 */
static uint32_t _ebpf_epoch_cpu_count = 0;

/**
 * @brief Enum of messages sent between CPUs.
 */
typedef enum _ebpf_epoch_cpu_message_type
{
    EBPF_EPOCH_CPU_MESSAGE_TYPE_PROPOSE_RELEASE_EPOCH, ///< This message is sent to CPU 0 to propose a new release
                                                       ///< epoch.
                                                       ///< CPU 0 declares the new current epoch and proposes it as the
                                                       ///< release epoch. Each CPU then queries the epoch for each
                                                       ///< thread linked to this CPU and sets the proposed release
                                                       ///< epoch in the message to the minimum of the local minima and
                                                       ///< the minima in the message. The message is then forwarded to
                                                       ///< the next CPU. The last CPU then sends an epoch commit
                                                       ///< message to CPU 0 with the final proposed release epoch.

    EBPF_EPOCH_CPU_MESSAGE_TYPE_COMMIT_RELEASE_EPOCH, ///< This message is sent to CPU 0 to commit the proposed release
                                                      ///< epoch.
                                                      ///< Each CPU then:
                                                      ///< 1. Clears the timer-armed flag.
                                                      ///< 2. Sets the released epoch to the proposed release epoch
                                                      ///< minus 1.
                                                      ///< 3. Releases any items in the free list that are eligible for
                                                      ///< reclamation.
                                                      ///< 4. Rearms the timer if need.
                                                      ///< 5. Forwards the message to the next CPU.
                                                      ///< The last CPU then sends an epoch computation complete message
                                                      ///< to CPU 0.
    EBPF_EPOCH_CPU_MESSAGE_TYPE_PROPOSE_EPOCH_COMPLETE, ///< This message is sent only to CPU 0 to signal that epoch
                                                        ///< computation is complete.
    EBPF_EPOCH_CPU_MESSAGE_TYPE_EXIT_EPOCH, ///< This message is used when a thread running with IRQL < DISPATCH calls
                                            ///< ebpf_epoch_exit on a different CPU than ebpf_epoch_enter. It is sent
                                            ///< from the CPU where the thread called ebpf_epoch_exit to the CPU where
                                            ///< the thread called ebpf_epoch_enter.
    EBPF_EPOCH_CPU_MESSAGE_TYPE_RUNDOWN_IN_PROGRESS, ///< This message is sent to each CPU to notify it that epoch code
                                                     ///< is shutting down and that no future timers should be armed and
                                                     ///< future messages should be ignored.
    EBPF_EPOCH_CPU_MESSAGE_TYPE_IS_FREE_LIST_EMPTY,  ///< This message is sent to each CPU to query if its local free
                                                     ///< list is empty.
} ebpf_epoch_cpu_message_type_t;

/**
 * @brief Message sent between CPUs.
 */
typedef struct _ebpf_epoch_cpu_message
{
    LIST_ENTRY list_entry; ///< List entry used to insert the message into the message queue.
    ebpf_epoch_cpu_message_type_t message_type;
    ebpf_work_queue_wakeup_behavior_t wake_behavior;
    union
    {
        struct
        {
            uint64_t current_epoch;          ///< The new current epoch.
            uint64_t proposed_release_epoch; ///< Minimum epoch of all threads on the CPU.
        } propose_epoch;
        struct
        {
            uint64_t released_epoch; ///< The newest epoch that can be released.
        } commit_epoch;
        struct
        {
            ebpf_epoch_state_t* epoch_state; ///< Epoch state to remove.
        } exit_epoch;
        struct
        {
            uint8_t unused; ///< Unused.
        } rundown_in_progress;
        struct
        {
            bool is_empty; ///< True if the free list is empty.
        } is_free_list_empty;
    } message;
    KEVENT completion_event; ///< Event to signal when the operation is complete.
} ebpf_epoch_cpu_message_t;

/**
 * @brief Timer used to schedule epoch computation.
 */
static KTIMER _ebpf_epoch_compute_release_epoch_timer;

/**
 * @brief Message used to compute the release epoch.
 */
static ebpf_epoch_cpu_message_t _ebpf_epoch_compute_release_epoch_message = {0};

/**
 * @brief DPC used to process timer expiration.
 */
static KDPC _ebpf_epoch_timer_dpc;

/**
 * @brief Type of entry in the free list.
 * There are two types of entries in the free list:
 * 1. Memory allocation. This is a block of memory that is returned to the memory pool.
 * 2. Work item. This is a work item that is invoked at the end of the epoch.
 */
typedef enum _ebpf_epoch_allocation_type
{
    EBPF_EPOCH_ALLOCATION_MEMORY,               ///< Memory allocation.
    EBPF_EPOCH_ALLOCATION_WORK_ITEM,            ///< Work item.
    EBPF_EPOCH_ALLOCATION_SYNCHRONIZATION,      ///< Synchronization object.
    EBPF_EPOCH_ALLOCATION_MEMORY_CACHE_ALIGNED, ///< Memory allocation that is cache aligned.
} ebpf_epoch_allocation_type_t;

/**
 * @brief Header for each entry in the free list.
 */
typedef struct _ebpf_epoch_allocation_header
{
    ebpf_list_entry_t list_entry; ///< List entry used to insert the item into the free list.
    int64_t freed_epoch;          ///< Epoch when the item was freed. Used to determine when the item can be released.
    ebpf_epoch_allocation_type_t entry_type; ///< Type of entry.
} ebpf_epoch_allocation_header_t;

static_assert(
    sizeof(ebpf_epoch_allocation_header_t) < EBPF_CACHE_LINE_SIZE, "Header size must be less than cache line");

/**
 * @brief This structure is used as a place holder when a custom action needs
 * to be performed on epoch end. Typically this is releasing memory that can't
 * be handled by the default allocator.
 */
typedef struct _ebpf_epoch_work_item
{
    ebpf_epoch_allocation_header_t header;                 ///< Header used to insert the item into the free list.
    cxplat_preemptible_work_item_t* preemptible_work_item; ///< Work item to invoke.
    void* callback_context;                                ///< Context to pass to the callback.
    const void (*callback)(_Inout_ void* context);         ///< Callback to invoke.
} ebpf_epoch_work_item_t;

typedef struct _ebpf_epoch_synchronization
{
    ebpf_epoch_allocation_header_t header; ///< Header used to insert the item into the free list.
    KEVENT event;                          ///< Event to signal.
} ebpf_epoch_synchronization_t;

/**
 * @brief Rundown reference used to wait for all work items to complete.
 */
cxplat_rundown_reference_t _ebpf_epoch_work_item_rundown_ref;

static void
_ebpf_epoch_release_free_list(_Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, int64_t released_epoch);

_IRQL_requires_(DISPATCH_LEVEL) static void _ebpf_epoch_messenger_worker(
    _Inout_ void* context, uint32_t cpu_id, _Inout_ ebpf_list_entry_t* message);

_Function_class_(KDEFERRED_ROUTINE) _IRQL_requires_(DISPATCH_LEVEL) static void _ebpf_epoch_timer_worker(
    _In_ KDPC* dpc, _In_opt_ void* cpu_entry, _In_opt_ void* message, _In_opt_ void* arg2);

_IRQL_requires_max_(APC_LEVEL) static void _ebpf_epoch_send_message_and_wait(
    _In_ ebpf_epoch_cpu_message_t* message, uint32_t cpu_id);

static void
_ebpf_epoch_send_message_async(_In_ ebpf_epoch_cpu_message_t* message, uint32_t cpu_id);

_IRQL_requires_same_ static void
_ebpf_epoch_insert_in_free_list(_In_ ebpf_epoch_allocation_header_t* header);

static _IRQL_requires_(DISPATCH_LEVEL) void _ebpf_epoch_arm_timer_if_needed(ebpf_epoch_cpu_entry_t* cpu_entry);

static void
_ebpf_epoch_work_item_callback(_In_ cxplat_preemptible_work_item_t* preemptible_work_item, void* context);

_Must_inspect_result_ ebpf_result_t
ebpf_epoch_initiate()
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value = EBPF_SUCCESS;
    uint32_t cpu_count;

    cxplat_initialize_rundown_protection(&_ebpf_epoch_work_item_rundown_ref);

    cpu_count = ebpf_get_cpu_count();

    _ebpf_epoch_cpu_count = cpu_count;

    _ebpf_epoch_cpu_table = cxplat_allocate(
        CXPLAT_POOL_FLAG_NON_PAGED | CXPLAT_POOL_FLAG_CACHE_ALIGNED,
        sizeof(ebpf_epoch_cpu_entry_t) * _ebpf_epoch_cpu_count,
        EBPF_POOL_TAG_EPOCH);
    if (!_ebpf_epoch_cpu_table) {
        return_value = EBPF_NO_MEMORY;
        goto Error;
    }

    ebpf_assert(EBPF_CACHE_ALIGN_POINTER(_ebpf_epoch_cpu_table) == _ebpf_epoch_cpu_table);

    // Initialize the per-CPU state.
    for (uint32_t cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[cpu_id];
        cpu_entry->current_epoch = 1;
        ebpf_list_initialize(&cpu_entry->epoch_state_list);
        ebpf_list_initialize(&cpu_entry->free_list);
    }

    // Initialize the message queue.
    for (uint32_t cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[cpu_id];
        LARGE_INTEGER interval;
        interval.QuadPart = EBPF_EPOCH_FLUSH_DELAY_IN_NANOSECONDS / EBPF_NS_PER_FILETIME;

        ebpf_result_t result = ebpf_timed_work_queue_create(
            &cpu_entry->work_queue, cpu_id, &interval, _ebpf_epoch_messenger_worker, cpu_entry);
        if (result != EBPF_SUCCESS) {
            return_value = result;
            goto Error;
        }
    }

    KeInitializeDpc(&_ebpf_epoch_timer_dpc, _ebpf_epoch_timer_worker, NULL);
    KeSetTargetProcessorDpc(&_ebpf_epoch_timer_dpc, 0);

    KeInitializeTimer(&_ebpf_epoch_compute_release_epoch_timer);

Error:
    if (return_value != EBPF_SUCCESS && _ebpf_epoch_cpu_table) {
        for (uint32_t cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
            ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[cpu_id];
            ebpf_timed_work_queue_destroy(cpu_entry->work_queue);
        }
        cxplat_free(
            _ebpf_epoch_cpu_table, CXPLAT_POOL_FLAG_NON_PAGED | CXPLAT_POOL_FLAG_CACHE_ALIGNED, EBPF_POOL_TAG_EPOCH);
        _ebpf_epoch_cpu_table = NULL;
    }

    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_epoch_terminate()
{
    EBPF_LOG_ENTRY();
    uint32_t cpu_id;
    ebpf_epoch_cpu_message_t rundown_message = {0};

    if (!_ebpf_epoch_cpu_table) {
        return;
    }

    rundown_message.message_type = EBPF_EPOCH_CPU_MESSAGE_TYPE_RUNDOWN_IN_PROGRESS;
    rundown_message.wake_behavior = EBPF_WORK_QUEUE_WAKEUP_ON_INSERT;
    _ebpf_epoch_send_message_and_wait(&rundown_message, 0);

    // Cancel the timer.
    KeCancelTimer(&_ebpf_epoch_compute_release_epoch_timer);

    // Wait for the active DPC to complete.
    KeFlushQueuedDpcs();

    for (cpu_id = 0; cpu_id < _ebpf_epoch_cpu_count; cpu_id++) {
        ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[cpu_id];
        // Release all memory that is still in the free list.
        _ebpf_epoch_release_free_list(cpu_entry, MAXINT64);
        ebpf_assert(ebpf_list_is_empty(&cpu_entry->free_list));
        ebpf_timed_work_queue_destroy(cpu_entry->work_queue);
    }

    // Wait for all work items to complete.
    cxplat_wait_for_rundown_protection_release(&_ebpf_epoch_work_item_rundown_ref);

    _ebpf_epoch_cpu_count = 0;

    cxplat_free(
        _ebpf_epoch_cpu_table, CXPLAT_POOL_FLAG_NON_PAGED | CXPLAT_POOL_FLAG_CACHE_ALIGNED, EBPF_POOL_TAG_EPOCH);
    _ebpf_epoch_cpu_table = NULL;
    EBPF_RETURN_VOID();
}

#pragma warning(push)
#pragma warning(disable : 28166) // warning C28166: Code analysis incorrectly reports that the function
                                 // 'ebpf_epoch_enter' does not restore the IRQL to the value that was current at
                                 // function entry.
_IRQL_requires_same_ void
ebpf_epoch_enter(_Out_ ebpf_epoch_state_t* epoch_state)
{
    epoch_state->irql_at_enter = ebpf_raise_irql_to_dispatch_if_needed();
    epoch_state->cpu_id = ebpf_get_current_cpu();

    ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[epoch_state->cpu_id];
    epoch_state->epoch = cpu_entry->current_epoch;
    ebpf_list_insert_tail(&cpu_entry->epoch_state_list, &epoch_state->epoch_list_entry);

    ebpf_lower_irql_from_dispatch_if_needed(epoch_state->irql_at_enter);
}
#pragma warning(pop)

#pragma warning(push)
#pragma warning( \
    disable : 28166) // warning C28166: Code analysis incorrectly reports that the function 'ebpf_epoch_exit'
                     // does not restore the IRQL to the value that was current at function entry.
_IRQL_requires_same_ void
ebpf_epoch_exit(_In_ ebpf_epoch_state_t* epoch_state)
{
    KIRQL old_irql = ebpf_raise_irql_to_dispatch_if_needed();

    // Assert the IRQL is the same as when ebpf_epoch_enter() was called.
    ebpf_assert(old_irql == epoch_state->irql_at_enter);

    uint32_t cpu_id = ebpf_get_current_cpu();

    // Special case: Thread has moved to a different CPU since entering the epoch.
    if (cpu_id != epoch_state->cpu_id) {
        // Assert that the IRQL is < DISPATCH_LEVEL. If it is DISPATCH_LEVEL, then the thread moved to a different CPU
        // (by dropping below DISPATCH_LEVEL) and calling ebpf_epoch_exit(). This is not allowed.
        EBPF_EPOCH_FAIL_FAST(FAST_FAIL_INVALID_ARG, epoch_state->irql_at_enter < DISPATCH_LEVEL);

        // Signal the other CPU to remove the thread entry.
        if (old_irql < DISPATCH_LEVEL) {
            KeLowerIrql(old_irql);
        }

        ebpf_epoch_cpu_message_t message = {0};
        message.message_type = EBPF_EPOCH_CPU_MESSAGE_TYPE_EXIT_EPOCH;
        message.message.exit_epoch.epoch_state = epoch_state;
        message.wake_behavior = EBPF_WORK_QUEUE_WAKEUP_ON_INSERT;

        // The other CPU will call ebpf_epoch_exit() on our behalf.
        // The epoch was entered at < DISPATCH_LEVEL but will now exit at DISPATCH_LEVEL. To prevent the assert above
        // from triggering, we need to set the irql_at_enter to DISPATCH_LEVEL.
        KIRQL saved_irql = epoch_state->irql_at_enter;
        epoch_state->irql_at_enter = DISPATCH_LEVEL;

        _ebpf_epoch_send_message_and_wait(&message, epoch_state->cpu_id);

        // Restore the irql at enter.
        epoch_state->irql_at_enter = saved_irql;
        return;
    }

    ebpf_list_remove_entry(&epoch_state->epoch_list_entry);
    _ebpf_epoch_arm_timer_if_needed(&_ebpf_epoch_cpu_table[cpu_id]);

    // If there are items in the work queue, flush them.
    if (!ebpf_timed_work_queue_is_empty(_ebpf_epoch_cpu_table[cpu_id].work_queue)) {
        ebpf_timed_work_queued_flush(_ebpf_epoch_cpu_table[cpu_id].work_queue);
    }

    ebpf_lower_irql_from_dispatch_if_needed(epoch_state->irql_at_enter);
}
#pragma warning(pop)

__drv_allocatesMem(Mem) _Must_inspect_result_
    _Ret_writes_maybenull_(size) void* ebpf_epoch_allocate_with_tag(size_t size, uint32_t tag)
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

_Must_inspect_result_
_Ret_writes_maybenull_(size) void* ebpf_epoch_allocate(size_t size)
{
    return ebpf_epoch_allocate_with_tag(size, EBPF_POOL_TAG_EPOCH);
}

_Must_inspect_result_
_Ret_writes_maybenull_(size) void* ebpf_epoch_allocate_cache_aligned_with_tag(size_t size, uint32_t tag)
{
    ebpf_assert(size);
    ebpf_epoch_allocation_header_t* header;

    size += EBPF_CACHE_LINE_SIZE;
    header = (ebpf_epoch_allocation_header_t*)ebpf_allocate_cache_aligned_with_tag(size, tag);
    if (header) {
        header = (ebpf_epoch_allocation_header_t*)((uint8_t*)header + EBPF_CACHE_LINE_SIZE);
    }

    return header;
}

void
ebpf_epoch_free(_Frees_ptr_opt_ void* memory)
{
    ebpf_epoch_allocation_header_t* header = (ebpf_epoch_allocation_header_t*)memory;

    if (!memory) {
        return;
    }

    header--;

    // Pool corruption or double free.
    EBPF_EPOCH_FAIL_FAST(FAST_FAIL_HEAP_METADATA_CORRUPTION, header->freed_epoch == 0);
    header->entry_type = EBPF_EPOCH_ALLOCATION_MEMORY;

    _ebpf_epoch_insert_in_free_list(header);
}

void
ebpf_epoch_free_cache_aligned(_Frees_ptr_opt_ void* memory)
{
    ebpf_epoch_allocation_header_t* header = (ebpf_epoch_allocation_header_t*)memory;

    if (!memory) {
        return;
    }

    header = (ebpf_epoch_allocation_header_t*)((uint8_t*)header - EBPF_CACHE_LINE_SIZE);

    // Pool corruption or double free.
    EBPF_EPOCH_FAIL_FAST(FAST_FAIL_HEAP_METADATA_CORRUPTION, header->freed_epoch == 0);
    header->entry_type = EBPF_EPOCH_ALLOCATION_MEMORY_CACHE_ALIGNED;

    _ebpf_epoch_insert_in_free_list(header);
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

    if (!cxplat_acquire_rundown_protection(&_ebpf_epoch_work_item_rundown_ref)) {
        ebpf_free(work_item);
        return NULL;
    }

    ebpf_result_t result = ebpf_allocate_preemptible_work_item(
        &work_item->preemptible_work_item, _ebpf_epoch_work_item_callback, work_item);
    if (result != EBPF_SUCCESS) {
        cxplat_release_rundown_protection(&_ebpf_epoch_work_item_rundown_ref);
        ebpf_free(work_item);
        return NULL;
    }

    return work_item;
}

void
ebpf_epoch_schedule_work_item(_Inout_ ebpf_epoch_work_item_t* work_item)
{
    work_item->header.entry_type = EBPF_EPOCH_ALLOCATION_WORK_ITEM;
    _ebpf_epoch_insert_in_free_list(&work_item->header);
}

void
ebpf_epoch_cancel_work_item(_In_opt_ _Frees_ptr_opt_ ebpf_epoch_work_item_t* work_item)
{
    if (!work_item) {
        return;
    }

    // Internal error. Work item has already been queued.
    ebpf_assert(work_item->header.list_entry.Flink == NULL);

    cxplat_free_preemptible_work_item(work_item->preemptible_work_item);
    ebpf_free(work_item);

    cxplat_release_rundown_protection(&_ebpf_epoch_work_item_rundown_ref);
}

_IRQL_requires_max_(PASSIVE_LEVEL) void ebpf_epoch_synchronize()
{
    if (!_ebpf_epoch_cpu_table) {
        return;
    }

    // Allocate on stack to avoid out of memory issues.
    ebpf_epoch_synchronization_t synchronization = {0};
    synchronization.header.entry_type = EBPF_EPOCH_ALLOCATION_SYNCHRONIZATION;

    KeInitializeEvent(&synchronization.event, NotificationEvent, false);
    _ebpf_epoch_insert_in_free_list(&synchronization.header);

    // Trigger epoch computation.
    ebpf_epoch_cpu_message_t message = {0};
    message.message_type = EBPF_EPOCH_CPU_MESSAGE_TYPE_PROPOSE_RELEASE_EPOCH;
    message.wake_behavior = EBPF_WORK_QUEUE_WAKEUP_ON_INSERT;
    _ebpf_epoch_send_message_and_wait(&message, 0);

    KeWaitForSingleObject(&synchronization.event, Executive, KernelMode, false, NULL);
}

bool
ebpf_epoch_is_free_list_empty(uint32_t cpu_id)
{
    ebpf_epoch_cpu_message_t message = {0};

    message.message_type = EBPF_EPOCH_CPU_MESSAGE_TYPE_IS_FREE_LIST_EMPTY;
    message.wake_behavior = EBPF_WORK_QUEUE_WAKEUP_ON_INSERT;

    _ebpf_epoch_send_message_and_wait(&message, cpu_id);

    return message.message.is_free_list_empty.is_empty;
}

/**
 * @brief Release any memory that is associated with expired epochs.
 * @param[in] cpu_entry CPU entry to release memory for.
 * @param[in] released_epoch The newest epoch that can be released.
 */
static void
_ebpf_epoch_release_free_list(_Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, int64_t released_epoch)
{
    ebpf_list_entry_t* entry;
    ebpf_epoch_allocation_header_t* header;

    // Drain the free list until there is an entry that is not older than released_epoch.
    while (!ebpf_list_is_empty(&cpu_entry->free_list)) {
        entry = cpu_entry->free_list.Flink;
        header = CONTAINING_RECORD(entry, ebpf_epoch_allocation_header_t, list_entry);
        if (header->freed_epoch <= released_epoch) {
            ebpf_list_remove_entry(entry);
            PrefetchForWrite(entry->Flink->Flink);
            switch (header->entry_type) {
            case EBPF_EPOCH_ALLOCATION_MEMORY:
                ebpf_free(header);
                break;
            case EBPF_EPOCH_ALLOCATION_WORK_ITEM: {
                ebpf_epoch_work_item_t* work_item = CONTAINING_RECORD(header, ebpf_epoch_work_item_t, header);
                cxplat_queue_preemptible_work_item(work_item->preemptible_work_item);
                break;
            }
            case EBPF_EPOCH_ALLOCATION_SYNCHRONIZATION: {
                ebpf_epoch_synchronization_t* synchronization =
                    CONTAINING_RECORD(header, ebpf_epoch_synchronization_t, header);
                KeSetEvent(&synchronization->event, 0, false);
                break;
            }
            case EBPF_EPOCH_ALLOCATION_MEMORY_CACHE_ALIGNED:
                ebpf_free_cache_aligned(header);
                break;
            default:
                // Pool corruption or internal error.
                EBPF_EPOCH_FAIL_FAST(FAST_FAIL_CORRUPT_LIST_ENTRY, !"Invalid entry type");
            }
        } else {
            break;
        }
    }

    // Arm the timer if needed.
    _ebpf_epoch_arm_timer_if_needed(cpu_entry);
}

/**
 * @brief Arm the _ebpf_epoch_compute_release_epoch_timer timer if the following conditions are met:
 * 1. The timer is not already armed.
 * 2. The free list is not empty.
 * 3. Rundown is not in progress.
 *
 * @param[in] cpu_entry CPU entry to check.
 */
_IRQL_requires_(DISPATCH_LEVEL) static void _ebpf_epoch_arm_timer_if_needed(ebpf_epoch_cpu_entry_t* cpu_entry)
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
    LARGE_INTEGER due_time;
    due_time.QuadPart = -(EBPF_EPOCH_FLUSH_DELAY_IN_NANOSECONDS / EBPF_NS_PER_FILETIME);
    KeSetTimer(&_ebpf_epoch_compute_release_epoch_timer, due_time, &_ebpf_epoch_timer_dpc);
    return;
}

/**
 * @brief Insert the item into the free list. If rundown is in progress, then
 * the item is freed or queued to run on a worker thread depending on the type
 * of item.
 * If rundown is not in progress, then the item is inserted into the free list and
 * the timer is armed if needed.
 *
 * @param[in] header Header of item to insert.
 */
#pragma warning(push)
#pragma warning(disable : 28166) //  warning C28166: The function '_ebpf_epoch_insert_in_free_list' does not restore the
                                 //  IRQL to the value that was current at function entry and is required to do so. IRQL
                                 //  was last set to 2 at line 587.
_IRQL_requires_same_ static void
_ebpf_epoch_insert_in_free_list(_In_ ebpf_epoch_allocation_header_t* header)
{
    KIRQL old_irql = ebpf_raise_irql_to_dispatch_if_needed();
    uint32_t cpu_id = ebpf_get_current_cpu();
    ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[cpu_id];

    if (cpu_entry->rundown_in_progress) {
        KeLowerIrql(old_irql);
        switch (header->entry_type) {
        case EBPF_EPOCH_ALLOCATION_MEMORY:
            ebpf_free(header);
            break;
        case EBPF_EPOCH_ALLOCATION_WORK_ITEM: {
            ebpf_epoch_work_item_t* work_item = CONTAINING_RECORD(header, ebpf_epoch_work_item_t, header);
            cxplat_queue_preemptible_work_item(work_item->preemptible_work_item);
            break;
        }
        case EBPF_EPOCH_ALLOCATION_SYNCHRONIZATION: {
            ebpf_epoch_synchronization_t* synchronization =
                CONTAINING_RECORD(header, ebpf_epoch_synchronization_t, header);
            KeSetEvent(&synchronization->event, 0, false);
            break;
        }
        default:
            ebpf_assert(!"Invalid entry type");
        }
        return;
    }

    header->freed_epoch = cpu_entry->current_epoch;

    ebpf_list_insert_tail(&cpu_entry->free_list, &header->list_entry);

    _ebpf_epoch_arm_timer_if_needed(cpu_entry);

    ebpf_lower_irql_from_dispatch_if_needed(old_irql);
}
#pragma warning(pop)

static uint32_t _ebpf_epoch_skipped_timers = 0;

/**
 * @brief DPC that runs when the _ebpf_epoch_compute_release_epoch_timer timer expires.
 * If rundown is in progress, this function exits immediately.
 * If release epoch computation is not in progress, then it is initiated.
 * If release epoch computation is in progress, then the timer is re-armed.
 * @param[in] dpc DPC that triggered this function.
 * @param[in] context Context passed to the DPC - not used.
 * @param[in] arg1 Not used.
 * @param[in] arg2 Not used.
 */
_Function_class_(KDEFERRED_ROUTINE) _IRQL_requires_(DISPATCH_LEVEL) static void _ebpf_epoch_timer_worker(
    _In_ KDPC* dpc, _In_opt_ void* context, _In_opt_ void* arg1, _In_opt_ void* arg2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);

    if (_ebpf_epoch_cpu_table[0].rundown_in_progress) {
        return;
    }

    if (!_ebpf_epoch_cpu_table[0].epoch_computation_in_progress) {
        _ebpf_epoch_cpu_table[0].epoch_computation_in_progress = true;
        _ebpf_epoch_skipped_timers = 0;
        memset(&_ebpf_epoch_compute_release_epoch_message, 0, sizeof(_ebpf_epoch_compute_release_epoch_message));
        _ebpf_epoch_compute_release_epoch_message.message_type = EBPF_EPOCH_CPU_MESSAGE_TYPE_PROPOSE_RELEASE_EPOCH;
        _ebpf_epoch_compute_release_epoch_message.wake_behavior = EBPF_WORK_QUEUE_WAKEUP_ON_TIMER;
        KeInitializeEvent(&_ebpf_epoch_compute_release_epoch_message.completion_event, NotificationEvent, false);
        _ebpf_epoch_send_message_async(&_ebpf_epoch_compute_release_epoch_message, 0);
    } else {
        _ebpf_epoch_skipped_timers++;
        LARGE_INTEGER due_time;
        due_time.QuadPart = -(EBPF_EPOCH_FLUSH_DELAY_IN_NANOSECONDS / EBPF_NS_PER_FILETIME);
        KeSetTimer(&_ebpf_epoch_compute_release_epoch_timer, due_time, &_ebpf_epoch_timer_dpc);
    }
}

/**
 * @brief DPC that runs when a message is sent between CPUs.
 */
typedef void (*ebpf_epoch_messenger_worker_t)(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, _Inout_ ebpf_epoch_cpu_message_t* message, uint32_t current_cpu);

/**
 * @brief Compute the next proposed release epoch and send it to the next CPU.
 * Message first is sent to CPU 0.
 * CPU == 0 declares the new current epoch and proposes it as the release epoch.
 * CPU != 0 sets current epoch to the new current epoch.
 * Each CPU then queries the epoch for each thread queued on that CPU and sets the proposed release epoch in the message
 * to the minimum of the local minima and the minima in the message. The message is then forwarded to the next CPU. Non
 * last CPU forwards the message to the next CPU. The last CPU then sends an
 * EBPF_EPOCH_CPU_MESSAGE_TYPE_COMMIT_RELEASE_EPOCH message to CPU 0 with the final proposed release epoch.
 *
 * @param[in] cpu_entry CPU entry to compute the epoch for.
 * @param[in] message Message to process.
 * @param[in] current_cpu Current CPU.
 */
void
_ebpf_epoch_messenger_propose_release_epoch(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, _Inout_ ebpf_epoch_cpu_message_t* message, uint32_t current_cpu)
{
    // Walk over each thread_entry in the epoch_state_list and compute the minimum epoch.
    ebpf_list_entry_t* entry = cpu_entry->epoch_state_list.Flink;
    ebpf_epoch_state_t* epoch_state;
    uint32_t next_cpu;

    // First CPU updates the current epoch and proposes the release epoch.
    if (current_cpu == 0) {
        cpu_entry->current_epoch++;
        message->message.propose_epoch.current_epoch = cpu_entry->current_epoch;
        message->message.propose_epoch.proposed_release_epoch = cpu_entry->current_epoch;
    }
    // Other CPUs update the current epoch.
    else {
        cpu_entry->current_epoch = message->message.propose_epoch.current_epoch;
    }

    // Put a memory barrier here to ensure that the write is not re-ordered.
    MemoryBarrier();

    // Previous CPU's minimum epoch.
    uint64_t minimum_epoch = message->message.propose_epoch.proposed_release_epoch;

    while (entry != &cpu_entry->epoch_state_list) {
        epoch_state = CONTAINING_RECORD(entry, ebpf_epoch_state_t, epoch_list_entry);
        minimum_epoch = min(minimum_epoch, epoch_state->epoch);
        entry = entry->Flink;
    }

    // Set the proposed release epoch to the minimum epoch seen so far.
    message->message.propose_epoch.proposed_release_epoch = minimum_epoch;

    // If this is the last CPU, then send a message to the first CPU to commit the release epoch.
    if (current_cpu == _ebpf_epoch_cpu_count - 1) {
        message->message.commit_epoch.released_epoch = minimum_epoch;
        message->message_type = EBPF_EPOCH_CPU_MESSAGE_TYPE_COMMIT_RELEASE_EPOCH;
        next_cpu = 0;
    } else {
        // Send the message to the next CPU.
        next_cpu = current_cpu + 1;
    }

    _ebpf_epoch_send_message_async(message, next_cpu);
}

/**
 * @brief Commit the release epoch and send it to the next CPU.
 * Message is sent to CPU 0.
 * Each CPU sets its released epoch to the proposed release epoch minus 1.
 * Each CPU then:
 * 1. Clears the timer-armed flag.
 * 2. Sets the released epoch to the proposed release epoch minus 1.
 * 3. Releases any items in the free list that are eligible for reclamation.
 * 4. Rearms the timer if need.
 * 5. Forwards the message to the next CPU.
 * The last CPU then sends a EBPF_EPOCH_CPU_MESSAGE_TYPE_PROPOSE_EPOCH_COMPLETE message to CPU 0.
 *
 * @param[in] cpu_entry CPU entry to rearm the timer for.
 * @param[in] message Message to process.
 * @param[in] current_cpu Current CPU.
 */
void
_ebpf_epoch_messenger_commit_release_epoch(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, _Inout_ ebpf_epoch_cpu_message_t* message, uint32_t current_cpu)
{
    uint32_t next_cpu;

    cpu_entry->timer_armed = false;
    // Set the released_epoch to the value computed by the EBPF_EPOCH_CPU_MESSAGE_TYPE_PROPOSE_RELEASE_EPOCH message.
    cpu_entry->released_epoch = message->message.commit_epoch.released_epoch - 1;

    // If this is the last CPU, send the message to the first CPU to complete the cycle.
    if (current_cpu != _ebpf_epoch_cpu_count - 1) {
        // Send the message to the next CPU.
        next_cpu = current_cpu + 1;
    } else {
        message->message_type = EBPF_EPOCH_CPU_MESSAGE_TYPE_PROPOSE_EPOCH_COMPLETE;
        next_cpu = 0;
    }

    _ebpf_epoch_send_message_async(message, next_cpu);

    _ebpf_epoch_release_free_list(cpu_entry, cpu_entry->released_epoch);
}

/**
 * @brief Complete the release epoch computation and allow the next epoch computation to start.
 * EBPF_EPOCH_CPU_MESSAGE_TYPE_PROPOSE_EPOCH_COMPLETE message:
 * Message is sent only to CPU 0.
 * CPU 0 clears the epoch computation in progress flag and signals the KEVENT associated with the message to signal any
 * waiting threads that the operation is completed.
 *
 * @param[in] cpu_entry CPU entry to mark the computation as complete for.
 * @param[in] message Message to process.
 * @param[in] current_cpu Current CPU.
 */
void
_ebpf_epoch_messenger_compute_epoch_complete(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, _Inout_ ebpf_epoch_cpu_message_t* message, uint32_t current_cpu)
{
    UNREFERENCED_PARAMETER(current_cpu);
    // If this is the timer's DPC, then mark the computation as complete.
    if (message == &_ebpf_epoch_compute_release_epoch_message) {
        cpu_entry->epoch_computation_in_progress = false;
    } else {
        // This is an adhoc flush. Signal the caller that the flush is complete.
        KeSetEvent(&message->completion_event, 0, FALSE);
    }
}

/**
 * @brief Remove the provided thread from this CPU's thread list and signal the completion event.
 * EBPF_EPOCH_CPU_MESSAGE_TYPE_EXIT_EPOCH message:
 * Message is sent from a thread that is exiting the epoch to the CPU that ebpf_epoch_enter was called on.
 * The CPU removes the ebpf_epoch_state_t from the per-CPU thread list and signals the KEVENT associated with the
 * message to signal any waiting threads that the operation is completed.
 *
 * @param[in] cpu_entry CPU entry to call ebpf_epoch_exit() for.
 * @param[in] message Message to process.
 * @param[in] current_cpu Current CPU.
 */
void
_ebpf_epoch_messenger_exit_epoch(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, _Inout_ ebpf_epoch_cpu_message_t* message, uint32_t current_cpu)
{
    UNREFERENCED_PARAMETER(current_cpu);
    UNREFERENCED_PARAMETER(cpu_entry);

    ebpf_epoch_exit(message->message.exit_epoch.epoch_state);
    KeSetEvent(&message->completion_event, 0, FALSE);
}

/**
 * @brief Message to notify each CPU that rundown is in progress.
 * EBPF_EPOCH_CPU_MESSAGE_TYPE_RUNDOWN_IN_PROGRESS message:
 * Message is sent to each CPU to notify it that epoch code is shutting down and that no future timers should be armed
 * and future messages should be ignored.
 *
 * @param[in] cpu_entry CPU entry to set the flag for.
 * @param[in] message Message to process.
 * @param[in] current_cpu Current CPU.
 */
void
_ebpf_epoch_messenger_rundown_in_progress(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, _Inout_ ebpf_epoch_cpu_message_t* message, uint32_t current_cpu)
{
    uint32_t next_cpu;
    cpu_entry->rundown_in_progress = true;
    // If this is the last CPU, then stop.
    if (current_cpu != _ebpf_epoch_cpu_count - 1) {
        // Send the message to the next CPU.
        next_cpu = current_cpu + 1;
    } else {
        // Signal the caller that rundown is complete.
        KeSetEvent(&message->completion_event, 0, FALSE);
        // Set next_cpu to UINT32_MAX to make code analysis happy.
        next_cpu = UINT32_MAX;
        return;
    }

    _ebpf_epoch_send_message_async(message, next_cpu);
}

/**
 * @brief Message to query if the free list is empty.
 * EBPF_EPOCH_CPU_MESSAGE_TYPE_IS_FREE_LIST_EMPTY message:
 * Message is sent to each CPU to query if its local free list is empty.
 *
 * @param[in] cpu_entry CPU entry to check.
 * @param[in] message Message to process.
 * @param[in] current_cpu Current CPU.
 */
void
_ebpf_epoch_messenger_is_free_list_empty(
    _Inout_ ebpf_epoch_cpu_entry_t* cpu_entry, _Inout_ ebpf_epoch_cpu_message_t* message, uint32_t current_cpu)
{
    UNREFERENCED_PARAMETER(current_cpu);
    message->message.is_free_list_empty.is_empty = ebpf_list_is_empty(&cpu_entry->free_list);
    KeSetEvent(&message->completion_event, 0, FALSE);
}

/**
 * @brief Array of worker functions for the ebpf epoch inter-CPU messaging system.
 */
static ebpf_epoch_messenger_worker_t _ebpf_epoch_messenger_workers[] = {
    _ebpf_epoch_messenger_propose_release_epoch,
    _ebpf_epoch_messenger_commit_release_epoch,
    _ebpf_epoch_messenger_compute_epoch_complete,
    _ebpf_epoch_messenger_exit_epoch,
    _ebpf_epoch_messenger_rundown_in_progress,
    _ebpf_epoch_messenger_is_free_list_empty};

/**
 * @brief Worker for the ebpf epoch inter-CPU messaging system.
 *
 * If rundown is in progress, then the message is ignored.
 *
 * @param[in] context Context passed to the DPC - not used.
 * @param[in] list_entry List entry that contains the message to process.
 */
_IRQL_requires_(DISPATCH_LEVEL) static void _ebpf_epoch_messenger_worker(
    _Inout_ void* context, uint32_t cpu_id, _Inout_ ebpf_list_entry_t* list_entry)
{
    UNREFERENCED_PARAMETER(context);
    ebpf_assert(ebpf_get_current_cpu() == cpu_id);
    ebpf_epoch_cpu_entry_t* cpu_entry = &_ebpf_epoch_cpu_table[cpu_id];
    ebpf_epoch_cpu_message_t* message = CONTAINING_RECORD(list_entry, ebpf_epoch_cpu_message_t, list_entry);

    // If rundown is in progress, then exit immediately.
    if (cpu_entry->rundown_in_progress) {
        return;
    }

    if (message->message_type > EBPF_COUNT_OF(_ebpf_epoch_messenger_workers) || message->message_type < 0) {
        ebpf_assert(!"Invalid message type");
        return;
    }

    _ebpf_epoch_messenger_workers[message->message_type](cpu_entry, message, cpu_id);
}

/**
 * @brief Send a message to the specified CPU and wait for it to complete.
 *
 * @param[in] message Message to send.
 * @param[in] cpu_id CPU to send the message to.
 * @param[in] flush If true, process all messages on the target CPU immediately.
 */
_IRQL_requires_max_(APC_LEVEL) static void _ebpf_epoch_send_message_and_wait(
    _In_ ebpf_epoch_cpu_message_t* message, uint32_t cpu_id)
{
    // First, check if the work queue ptr for the specified _ebpf_epoch_cpu_table entry is valid.
    // This ptr can be null if ebpf_epoch_initiate() fails to create a valid work queue for this
    // entry. That failure leads to a call to ebpf_epoch_terminate() which ends up here with an
    // entry with a null work_queue ptr.
    if (_ebpf_epoch_cpu_table[cpu_id].work_queue) {

        // Initialize the completion event.
        KeInitializeEvent(&message->completion_event, NotificationEvent, FALSE);

        // Queue the message to the specified CPU.
        ebpf_timed_work_queue_insert(
            _ebpf_epoch_cpu_table[cpu_id].work_queue, &message->list_entry, message->wake_behavior);

        // Wait for the message to complete.
        KeWaitForSingleObject(&message->completion_event, Executive, KernelMode, FALSE, NULL);
    }
}

/**
 * @brief Send a message to the specified CPU asynchronously.
 *
 * @param[in] message Message to send.
 * @param[in] cpu_id CPU to send the message to.
 * @param[in] flush If true, process all messages on the target CPU immediately.
 */
static void
_ebpf_epoch_send_message_async(_In_ ebpf_epoch_cpu_message_t* message, uint32_t cpu_id)
{
    // Queue the message to the specified CPU.
    ebpf_timed_work_queue_insert(
        _ebpf_epoch_cpu_table[cpu_id].work_queue, &message->list_entry, message->wake_behavior);
}

/**
 * @brief Callback for ebpf_preemptible_work_item_t that calls the callback
 * function in ebpf_epoch_work_item_t.
 *
 * @param[in] context The ebpf_epoch_work_item_t to process.
 */
static void
_ebpf_epoch_work_item_callback(_In_ cxplat_preemptible_work_item_t* preemptible_work_item, void* context)
{
    ebpf_epoch_work_item_t* work_item = (ebpf_epoch_work_item_t*)context;
    work_item->callback(work_item->callback_context);
    // Internal consistency check.
    ebpf_assert(preemptible_work_item == work_item->preemptible_work_item);
    cxplat_free_preemptible_work_item(preemptible_work_item);
    ebpf_free(work_item);

    cxplat_release_rundown_protection(&_ebpf_epoch_work_item_rundown_ref);
}
