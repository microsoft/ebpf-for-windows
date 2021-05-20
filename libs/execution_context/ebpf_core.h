/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include "ebpf_platform.h"
#include "ebpf_protocol.h"

#ifdef __cplusplus
extern "C"
{
#endif
#include "ebpf_protocol.h"

    extern GUID ebpf_global_helper_function_interface_id;

    typedef uint32_t(__stdcall* ebpf_hook_function)(uint8_t*);

    /**
     * @brief Initialize the eBPF core execution context.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_core_initiate();

    /**
     * @brief Uninitialize the eBPF core execution context.
     *
     */
    void
    ebpf_core_terminate();

    /**
     * @brief Invoke an operations on the eBPF execution context that was issued
     *  by the user mode library.
     *
     * @param[in] operation_id Identifier of the operation to execute.
     * @param[in] input_buffer Encoded buffer containing parameters for this
     *  operaton.
     * @param[out] output_buffer Pointer to memory that will contain the
     *  encoded result parameters for this operation.
     * @param[in] output_buffer_length Length of the output buffer.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_core_invoke_protocol_handler(
        ebpf_operation_id_t operation_id,
        _In_ const void* input_buffer,
        _Out_writes_bytes_(output_buffer_length) void* output_buffer,
        uint16_t output_buffer_length);

    /**
     * @brief Query properties about an operation.
     *
     * @param[in] operation_id Identifier of the operation to query.
     * @param[out] minimum_request_size Minimum size of a request buffer for
     *  this operation.
     * @param[out] minimum_reply_size Minimum size of the reply buffer for this
     *  operation.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NOT_SUPPORTED The operation id is not valid.
     */
    ebpf_result_t
    ebpf_core_get_protocol_handler_properties(
        ebpf_operation_id_t operation_id, _Out_ size_t* minimum_request_size, _Out_ size_t* minimum_reply_size);

#ifdef __cplusplus
}
#endif
