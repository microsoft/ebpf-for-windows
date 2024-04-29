// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_core_structs.h"
#include "ebpf_object.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef bool (*ebpf_compare_object_t)(_In_ const ebpf_base_object_t* object, _In_opt_ const void* context);

    /**
     * @brief Initialize the global handle table.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     */
    _Must_inspect_result_ ebpf_result_t
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
     * @param[in, out] object Object to write to.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_handle_create(_Out_ ebpf_handle_t* handle, _Inout_ struct _ebpf_base_object* object);

    /**
     * @brief Remove an existing handle from the handle table and release its
     *  reference on the object.
     *
     * @param[in] handle Handle to be released.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_INVALID_HANDLE The provided handle is not valid.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_handle_close(ebpf_handle_t handle);

    /**
     * @brief Find the handle in the handle table, acquire a reference to
     *  the object and return it.
     *
     * @param[in] handle Handle to find in table.
     * @param[out] object Pointer to memory that contains object success.
     * @param[in] file_id File ID of the caller.
     * @param[in] line Line number of the caller.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_OBJECT The provided handle is not valid.
     */
    _IRQL_requires_max_(PASSIVE_LEVEL) ebpf_result_t ebpf_reference_base_object_by_handle(
        ebpf_handle_t handle,
        _In_opt_ ebpf_compare_object_t compare_function,
        _In_opt_ const void* context,
        _Outptr_ struct _ebpf_base_object** object,
        uint32_t file_id,
        uint32_t line);

#ifdef __cplusplus
}
#endif
