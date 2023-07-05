// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"
#include "framework.h"

/// @brief Proxy to driver dispatch table.

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Initialize the eBPF core execution context.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    typedef _Must_inspect_result_ ebpf_result_t (*ebpf_core_initiate_t)();

    /**
     * @brief Uninitialize the eBPF core execution context.
     *
     */
    typedef void (*ebpf_core_terminate_t)();

    /**
     * @brief Invoke an operations on the eBPF execution context that was issued
     *  by the user mode library.
     *
     * @param[in] operation_id Identifier of the operation to execute.
     * @param[in] input_buffer Encoded buffer containing parameters for this
     *  operation.
     * @param[out] output_buffer Pointer to memory that will contain the
     *  encoded result parameters for this operation.
     * @param[in] output_buffer_length Length of the output buffer.
     * @param[in, out] async_context Async context to be passed to on_complete.
     * @param[in] on_complete Callback to be invoked when the operation is complete.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    typedef _Must_inspect_result_ ebpf_result_t (*ebpf_core_invoke_protocol_handler_t)(
        ebpf_operation_id_t operation_id,
        _In_reads_bytes_(input_buffer_length) const void* input_buffer,
        uint16_t input_buffer_length,
        _Out_writes_bytes_opt_(output_buffer_length) void* output_buffer,
        uint16_t output_buffer_length,
        _Inout_opt_ void* async_context,
        _In_opt_ void (*on_complete)(_Inout_ void*, size_t, ebpf_result_t));

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
    typedef _Must_inspect_result_ ebpf_result_t (*ebpf_core_get_protocol_handler_properties_t)(
        ebpf_operation_id_t operation_id,
        _Out_ size_t* minimum_request_size,
        _Out_ size_t* minimum_reply_size,
        _Out_ bool* async);

    /**
     * @brief Cancel an async protocol operation that returned EBPF_PENDING from
     * ebpf_core_dispatch_table.invoke_protocol_handler.
     *
     * @param[in, out] async_context Async context passed to ebpf_core_dispatch_table.invoke_protocol_handler.
     * @retval true Operation was canceled.
     * @retval false Operation was already completed.
     */
    typedef bool (*ebpf_core_cancel_protocol_handler_t)(_Inout_ void* async_context);

    /**
     * @brief Close the FsContext2 from a file object.
     *
     * @param[in] context The FsContext2 from a fileobject to close.
     */
    typedef void (*ebpf_core_close_context_t)(_In_opt_ void* context);

    typedef struct _ebpf_core_dispatch_table
    {
        uint32_t size;
        uint32_t version;
        ebpf_core_initiate_t initiate;
        ebpf_core_terminate_t terminate;
        ebpf_core_invoke_protocol_handler_t invoke_protocol_handler;
        ebpf_core_get_protocol_handler_properties_t get_protocol_handler_properties;
        ebpf_core_cancel_protocol_handler_t cancel_protocol_handler;
        ebpf_core_close_context_t close_context;
    } ebpf_core_dispatch_table_t;

    extern ebpf_core_dispatch_table_t ebpf_core_dispatch_table;

#ifdef __cplusplus
} // extern "C"
#endif
