// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_object.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef uint64_t ebpf_handle_t;

    /**
     * @brief Initialize the global handle table.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     */
    ebpf_result_t
    ebpf_handle_table_initiate();

    /**
     * @brief Terminate the global handle table.
     *
     */
    void
    ebpf_handle_table_terminate();

    /**
     * @brief Create a handle that holds a reference on the object.
     *
     * @param[out] handle Pointer to memory that contains the handle on success.
     * @param[in] object Object to be referenced by this handle.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_handle_create(ebpf_handle_t* handle, ebpf_object_t* object);

    /**
     * @brief Remove an existing handle from the handle table and release its
     *  reference on the object.
     *
     * @param[in] handle Handle to be released.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_INVALID_HANDLE The provided handle is not valid.
     */
    ebpf_result_t
    ebpf_handle_close(ebpf_handle_t handle);

    /**
     * @brief Find the handle in the handle table, verify the type matches,
     *  acquire a reference to the object and return it.
     *
     * @param[in] handle Handle to find in table.
     * @param[in] object_type Object type to match.
     * @param[out] object Pointer to memory that contains object success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_INVALID_HANDLE The provided handle is not valid.
     */
    ebpf_result_t
    ebpf_reference_object_by_handle(ebpf_handle_t handle, ebpf_object_type_t object_type, ebpf_object_t** object);

#ifdef __cplusplus
}
#endif
