// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Initialize the eBPF state tracking module.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_state_initiate();

    /**
     * @brief Uninitialize the eBPF state tracking module.
     *
     */
    void
    ebpf_state_terminate();

    /**
     * @brief Allocate a new index in the state tracker.
     *
     * @param[out] new_index Pointer to memory that contains the index on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_state_allocate_index(_Out_ size_t* new_index);

    /**
     * @brief Store a value in the state tracker.
     *
     * @param[in] index Assigned for storing state.
     * @param[in] value Value to be stored.
     * @param[in] execution_context_state Execution context state.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_state_store(size_t index, uintptr_t value, _In_ const ebpf_execution_context_state_t* execution_context_state);

    /**
     * @brief Load a value in the state tracker.
     *
     * @param[in] index Assigned for storing state.
     * @param[out] value Value to be loaded.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_state_load(size_t index, _Out_ uintptr_t* value);

#ifdef __cplusplus
}
#endif
