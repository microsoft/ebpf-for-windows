// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Library to tie an asynchronous action initiator and an action handler together.
// There flow is as follows:
//
// 1) Action initiator calls ebpf_completion_set_completion_callback to associate their context with a completion
// method.
//
// 2) Action initiator calls handler to start the asynchronous action.
//
// 3) Action handler calls ebpf_completion_set_cancel_callback to permit it to be notified if a cancellation occurs.
//
// 4) Action handler starts the asynchronous operation and returns to action initiator.
//
// 5) a) Success path: Action handler calls ebpf_completion_complete to notify the action initiator that the action has
// completed.
//
// 5) b) Cancellation path: Action initiator calls ebpf_completion_cancel to notify the action handler that
// the request has been canceled.
//
// Notes:
//
// 1) ebpf_completion_complete and ebpf_completion_cancel can be called
// concurrently, with one becoming a no-op.
//
// 2) Action initiator must not re-use context until after prior actions are
// completed or canceled.
//
// 3) Action handler must register for cancellation prior to returning to action initiator.

#pragma once
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Initialize the completion tracking module.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_completion_initiate();

    /**
     * @brief Shutdown the completion tracking module.
     *
     */
    void
    ebpf_completion_terminate();

    /**
     * @brief Set a completion function to be called when actions associated with this context complete.
     *
     * @param context Context of action to track.
     * @param on_complete Function to call when the action associated with this context completes.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_completion_set_completion_callback(
        _In_ void* context, _In_ void (*on_complete)(_In_ void* context, ebpf_result_t result));

    /**
     * @brief Set a cancellation function to be called when actions associated with this context are cancelled.
     *
     * @param context Context of action to track.
     * @param cancelation_context Context to pass when this action is cancelled.
     * @param on_cancel Function to call this action is canceled.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NOT_FOUND The action context hasn't been registered.
     */
    ebpf_result_t
    ebpf_completion_set_cancel_callback(
        _In_ void* context, _In_ void* cancelation_context, _In_ void (*on_cancel)(_In_ void* cancelation_context));

    /**
     * @brief Cancel the action associated with this context.
     *
     * @param context Context associated with the action.
     * @return true Action was cancelled.
     * @return false Action was already completed.
     */
    bool
    ebpf_completion_cancel(_In_ void* context);

    /**
     * @brief Complete the action associated with this context.
     *
     * @param context Context associated with the action.
     * @param result
     * @return true Action was cancelled.
     * @return false Action was already completed.
     */
    bool
    ebpf_completion_complete(_In_ void* context, ebpf_result_t result);

#ifdef __cplusplus
}
#endif
