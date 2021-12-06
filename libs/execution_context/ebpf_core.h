// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_platform.h"
#include "ebpf_protocol.h"
#include "ebpf_program_types.h"

#ifdef __cplusplus
extern "C"
{
#endif
#include "ebpf_protocol.h"

    extern ebpf_helper_function_prototype_t* ebpf_core_helper_function_prototype;
    extern uint32_t ebpf_core_helper_functions_count;

    extern GUID ebpf_general_helper_function_interface_id;

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
        _Out_writes_bytes_opt_(output_buffer_length) void* output_buffer,
        uint16_t output_buffer_length,
        _In_opt_ void* async_context,
        _In_opt_ void (*on_complete)(_In_ void*, size_t, ebpf_result_t));

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
        ebpf_operation_id_t operation_id,
        _Out_ size_t* minimum_request_size,
        _Out_ size_t* minimum_reply_size,
        _Out_ bool* async);

    /**
     * @brief Cancel an async protocol operation that returned EBPF_PENDING from ebpf_core_invoke_protocol_handler.
     *
     * @param[in] async_context Async context passed to ebpf_core_invoke_protocol_handler.
     * @retval true Operation was canceled.
     * @retval false Operation was already completed.
     */
    bool
    ebpf_core_cancel_protocol_handler(_In_ void* async_context);

    /**
     * @brief Computes difference of checksum values for two input raw buffers using 1's complement arithmetic.
     *
     * @param[in] from Pointer to first raw buffer.
     * @param[in] from_size Length of the "from" buffer. Must be a multiple of 4.
     * @param[in] to Pointer to the second raw buffer, whose checksum will be subtracted from that of the "from" buffer.
     * @param[in] to_size Length of the "to" buffer. Must be a multiple of 4.
     * @param[in] seed  An optional integer that can be added to the value, which can be used to carry result of a
     * previous csum_diff operation.
     *
     * @returns The checksum delta on success, or <0 on failure.
     */
    int
    ebpf_core_csum_diff(
        _In_reads_bytes_opt_(from_size) const void* from,
        int from_size,
        _In_reads_bytes_opt_(to_size) const void* to,
        int to_size,
        int seed);

#ifdef __cplusplus
}
#endif
