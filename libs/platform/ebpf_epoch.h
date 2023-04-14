// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct _ebpf_epoch_work_item ebpf_epoch_work_item_t;
    typedef struct _ebpf_epoch_state ebpf_epoch_state_t;

    /**
     * @brief Initialize the eBPF epoch tracking module.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_epoch_initiate();

    /**
     * @brief Uninitialize the eBPF epoch tracking module.
     *
     */
    void
    ebpf_epoch_terminate();

    /**
     * @brief Called prior to touching memory with lifetime under epoch control.
     * @returns Pointer to epoch state that must be passed to ebpf_epoch_exit.
     */
    ebpf_epoch_state_t*
    ebpf_epoch_enter();

    /**
     * @brief Called after touching memory with lifetime under epoch control.
     * @param[in] epoch_state Pointer to epoch state returned by ebpf_epoch_enter.
     */
    void
    ebpf_epoch_exit(_In_ ebpf_epoch_state_t* epoch_state);

    /**
     * @brief Allocate memory under epoch control.
     * @param[in] size Size of memory to allocate
     * @returns Pointer to memory block allocated, or null on failure.
     */
    _Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_epoch_allocate(size_t size);

    /**
     * @brief Allocate memory under epoch control with tag.
     * @param[in] size Size of memory to allocate
     * @param[in] tag Pool tag to use.
     * @returns Pointer to memory block allocated, or null on failure.
     */
    _Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_epoch_allocate_with_tag(size_t size, uint32_t tag);

    /**
     * @brief Free memory under epoch control.
     * @param[in] memory Allocation to be freed once epoch ends.
     */
    void
    ebpf_epoch_free(_Frees_ptr_opt_ void* memory);

    /**
     * @Brief Release any memory that is associated with expired epochs.
     */
    void
    ebpf_epoch_flush();

    /**
     * @brief Allocate an epoch work item; a work item that can be scheduled to
     * run when the current epoch ends. Allocated work items must either be
     * scheduled or canceled.
     *
     * @param[in] callback_context Context to pass to the callback function.
     * @param[in] callback Callback function to run on epoch end.
     * @return Pointer to work item that can be scheduled.
     */
    ebpf_epoch_work_item_t*
    ebpf_epoch_allocate_work_item(
        _In_ const void* callback_context, _In_ const void (*callback)(_Inout_ void* context));

    /**
     * @brief Schedule a previously allocated work-item to run when the current
     * epoch ends.
     *
     * @param[in, out] work_item Pointer to work item to run on epoch end.
     */
    void
    ebpf_epoch_schedule_work_item(_Inout_ ebpf_epoch_work_item_t* work_item);

    /**
     * @brief Cancels a previously allocated work-item. The work-item will not
     * run when the current epoch ends.
     *
     * @param[in] work_item Pointer to work item to free.
     */
    void
    ebpf_epoch_cancel_work_item(_Inout_ ebpf_epoch_work_item_t* work_item);

    /**
     * @brief Check the state of the free list on a CPU.
     *
     * @param[in] cpu_id CPU to check.
     * @retval true Free list is empty.
     * @retval false Free list is not empty.
     */
    bool
    ebpf_epoch_is_free_list_empty(uint32_t cpu_id);

#ifdef __cplusplus
}
#endif
