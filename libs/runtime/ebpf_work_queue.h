// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief A timed work queue. Entries in the work queue are executed
     * either after a fixed interval or when the queue is polled. The purpose of this
     * work queue is to allow for deferred execution of work items that are not
     * time critical and can be batched together with other work via the poll API.
     */
    typedef struct _ebpf_timed_work_queue ebpf_timed_work_queue_t;

    typedef _IRQL_requires_(DISPATCH_LEVEL) void (*ebpf_timed_work_queue_callback_t)(
        _Inout_ void* context, uint32_t cpu_id, _Inout_ ebpf_list_entry_t*);

    /**
     * @brief Create a timed work queue.
     *
     * @param[out] work_queue Pointer to memory that contains the work queue on success.
     * @param[in] cpu_id The CPU to run the work queue on.
     * @param[in] interval The interval at which to run the work queue.
     * @param[in] callback The callback to execute for each work item.
     * @param[in] context The context to pass to the callback.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_timed_work_queue_create(
        _Out_ ebpf_timed_work_queue_t** work_queue,
        uint32_t cpu_id,
        LARGE_INTEGER* interval,
        ebpf_timed_work_queue_callback_t callback,
        void* context);

    /**
     * @brief Destroy a timed work queue.
     *
     * @param[in] work_queue The timed work queue to destroy.
     */
    void
    ebpf_timed_work_queue_destroy(_In_ ebpf_timed_work_queue_t* work_queue);

    /**
     * @brief Insert a work item into the timed work queue. If immediate is true, the timer will fire immediately.
     *
     * @param[in] work_queue The work queue to insert the work item into.
     * @param[in] work_item The work item to insert.
     * @param[in] flush Fire the timer immediately.
     */
    void
    ebpf_timed_work_queue_insert(
        _In_ ebpf_timed_work_queue_t* work_queue, _In_ ebpf_list_entry_t* work_item, bool flush);

    /**
     * @brief Check if the timed work queue is empty without acquiring the lock.
     *
     * @param[in] work_queue The work queue to check.
     * @return true The work queue is empty.
     * @return false The work queue is not empty.
     */
    bool
    ebpf_timed_work_queue_is_empty(_In_ ebpf_timed_work_queue_t* work_queue);

    /**
     * @brief Execute the callback for all work items in the timed work queue.
     *
     * @param[in] work_queue The work queue to execute the callback for.
     */
    void
    ebpf_timed_work_queued_poll(_In_ ebpf_timed_work_queue_t* work_queue);

#ifdef __cplusplus
}
#endif