// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Library to tie an asynchronous action initiator and an action handler together.
// The flow is as follows:
//
// 1) Action initiator calls ebpf_async_set_completion_callback to associate their context with a completion
// method.
//
// 2) Action initiator calls handler to start the asynchronous action.
//
// 3) Action handler calls ebpf_async_set_cancel_callback to permit it to be notified if a cancellation occurs.
//
// 4) Action handler starts the asynchronous operation and returns to action initiator.
//
// 5) (optional) Action initiator calls ebpf_async_cancel to notify the action handler that the request has been
// canceled.
//
// 6) Action handler calls ebpf_async_complete to notify the action initiator that the action has completed.
//
//
// Notes:
//
// 1) ebpf_async_complete and ebpf_async_cancel can be called
// concurrently, with cancellation being a no-op on a completed action.
//
// 2) Action initiator must not re-use context until after prior actions are
// completed.
//
// 3) Action handler must register for cancellation prior to returning to action initiator.

#pragma once
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Initialize the async module.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_async_initiate();

    /**
     * @brief Shut down the async module.
     *
     */
    void
    ebpf_async_terminate();

    /**
     * @brief Set a completion function to be called when actions associated with this context complete.
     *
     * @param[in] context Context of action to track.
     * @param[in] on_complete Function to call when the action associated with
     * this context completes.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_async_set_completion_callback(_In_ void* context, _In_ void (*on_complete)(_In_ void*, size_t, ebpf_result_t));

    /**
     * @brief Set a cancellation function to be called when actions associated with this context are canceled.
     *
     * @param[in] context Context of action to track.
     * @param[in] cancellation_context Context to pass when this action is canceled.
     * @param[in] on_cancel Function to call if this action is canceled.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT The action context hasn't been registered.
     */
    ebpf_result_t
    ebpf_async_set_cancel_callback(
        _In_ void* context, _In_ void* cancellation_context, _In_ void (*on_cancel)(_In_ void* cancellation_context));

    /**
     * @brief Cancel the action associated with this context.
     *
     * @param[in] context Context associated with the action.
     * @retval true Action was canceled.
     * @retval false Action was already completed.
     */
    bool
    ebpf_async_cancel(_In_ void* context);

    /**
     * @brief Complete the action associated with this context.
     *
     * @param[in] context Context associated with the action.
     * @param[in] output_buffer_length Length (in bytes) of the buffer containing the result of the async operation.
     * @param[in] result The outcome of the action.
     */
    void
    ebpf_async_complete(_In_ void* context, size_t output_buffer_length, ebpf_result_t result);

#ifdef __cplusplus
}
#endif
