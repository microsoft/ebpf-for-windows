// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_work_queue.h"

typedef struct _ebpf_timed_work_queue
{
    KTIMER timer;
    KDPC dpc;
    ebpf_list_entry_t work_items;
    ebpf_lock_t lock;
    bool timer_armed;
    LARGE_INTEGER interval;
    ebpf_timed_work_queue_callback_t callback;
    void* context;
    uint32_t cpu_id;
} ebpf_timed_work_queue_t;

KDEFERRED_ROUTINE _ebpf_timed_work_queue_timer_callback;

void
_ebpf_timed_work_queue_timer_callback(
    _In_ KDPC* dpc, _In_opt_ void* deferred_context, _In_opt_ void* system_argument1, _In_opt_ void* system_argument2);

_Must_inspect_result_ ebpf_result_t
ebpf_timed_work_queue_create(
    _Out_ ebpf_timed_work_queue_t** work_queue,
    uint32_t cpu_id,
    _In_ LARGE_INTEGER* interval,
    _In_ ebpf_timed_work_queue_callback_t callback,
    _In_ void* context)
{
    ebpf_timed_work_queue_t* local_work_queue = NULL;
    ebpf_result_t return_value;

    local_work_queue = ebpf_allocate(sizeof(ebpf_timed_work_queue_t));
    if (!local_work_queue) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    local_work_queue->callback = callback;
    local_work_queue->context = context;
    local_work_queue->interval = *interval;
    local_work_queue->cpu_id = cpu_id;

    ebpf_lock_create(&local_work_queue->lock);

    ebpf_list_initialize(&local_work_queue->work_items);

    KeInitializeTimer(&local_work_queue->timer);
    KeInitializeDpc(&local_work_queue->dpc, _ebpf_timed_work_queue_timer_callback, local_work_queue);

    PROCESSOR_NUMBER processor_number;
    NTSTATUS status = KeGetProcessorNumberFromIndex(cpu_id, &processor_number);
    if (!NT_SUCCESS(status)) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    status = KeSetTargetProcessorDpcEx(&local_work_queue->dpc, &processor_number);
    if (!NT_SUCCESS(status)) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    *work_queue = local_work_queue;
    local_work_queue = NULL;
    return_value = EBPF_SUCCESS;

Done:
    ebpf_timed_work_queue_destroy(local_work_queue);

    return return_value;
}

void
ebpf_timed_work_queue_destroy(_In_opt_ ebpf_timed_work_queue_t* work_queue)
{
    if (!work_queue) {
        return;
    }

    // Cancel the timer.
    KeCancelTimer(&work_queue->timer);

    // Wait for the DPC to complete.
    KeFlushQueuedDpcs();

    // Destroy the lock.
    ebpf_lock_destroy(&work_queue->lock);

    // Free the work queue.
    ebpf_free(work_queue);
}

void
ebpf_timed_work_queue_insert(
    _In_ ebpf_timed_work_queue_t* work_queue,
    _In_ ebpf_list_entry_t* work_item,
    ebpf_work_queue_wakeup_behavior_t wake_behavior)
{
    ebpf_lock_state_t lock_state;
    bool timer_armed;

    lock_state = ebpf_lock_lock(&work_queue->lock);

    timer_armed = work_queue->timer_armed;
    ebpf_list_insert_tail(&work_queue->work_items, work_item);

    if (wake_behavior == EBPF_WORK_QUEUE_WAKEUP_ON_INSERT) {
        KeCancelTimer(&work_queue->timer);
        work_queue->timer_armed = false;
        KeInsertQueueDpc(&work_queue->dpc, NULL, NULL);
    } else if (!timer_armed) {
        LARGE_INTEGER due_time;
        due_time.QuadPart = -work_queue->interval.QuadPart;
        KeSetTimer(&work_queue->timer, due_time, &work_queue->dpc);
        work_queue->timer_armed = true;
    }

    ebpf_lock_unlock(&work_queue->lock, lock_state);
}

bool
ebpf_timed_work_queue_is_empty(_In_ ebpf_timed_work_queue_t* work_queue)
{
    return ebpf_list_is_empty(&work_queue->work_items);
}

void
ebpf_timed_work_queued_flush(_In_ ebpf_timed_work_queue_t* work_queue)
{
    ebpf_lock_state_t lock_state;
    ebpf_list_entry_t* work_item;

    lock_state = ebpf_lock_lock(&work_queue->lock);

    if (work_queue->timer_armed) {
        KeCancelTimer(&work_queue->timer);
        work_queue->timer_armed = false;
    }

    while (!ebpf_list_is_empty(&work_queue->work_items)) {
        work_item = work_queue->work_items.Flink;
        ebpf_list_remove_entry(work_item);
        ebpf_lock_unlock(&work_queue->lock, lock_state);
        work_queue->callback(work_queue->context, work_queue->cpu_id, work_item);
        lock_state = ebpf_lock_lock(&work_queue->lock);
    }

    ebpf_lock_unlock(&work_queue->lock, lock_state);
}

void
_ebpf_timed_work_queue_timer_callback(
    _In_ KDPC* dpc, _In_opt_ void* context, _In_opt_ void* system_argument1, _In_opt_ void* system_argument2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(system_argument1);
    UNREFERENCED_PARAMETER(system_argument2);
    ebpf_timed_work_queue_t* work_queue = (ebpf_timed_work_queue_t*)context;
    if (work_queue) {
        ebpf_timed_work_queued_flush(work_queue);
    }
}
