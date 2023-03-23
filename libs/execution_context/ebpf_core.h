// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_object.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_protocol.h"

#ifdef __cplusplus
extern "C"
{
#endif
#include "ebpf_protocol.h"

    extern ebpf_helper_function_prototype_t* ebpf_core_helper_function_prototype;
    extern uint32_t ebpf_core_helper_functions_count;

    extern GUID ebpf_program_information_extension_interface_id;
    extern GUID ebpf_hook_extension_interface_id;

    extern GUID ebpf_general_helper_function_module_id;

    typedef uint32_t(__stdcall* ebpf_hook_function)(uint8_t*);

    /**
     * @brief Initialize the eBPF core execution context.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
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
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_invoke_protocol_handler(
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
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_get_protocol_handler_properties(
        ebpf_operation_id_t operation_id,
        _Out_ size_t* minimum_request_size,
        _Out_ size_t* minimum_reply_size,
        _Out_ bool* async);

    /**
     * @brief Cancel an async protocol operation that returned EBPF_PENDING from ebpf_core_invoke_protocol_handler.
     *
     * @param[in, out] async_context Async context passed to ebpf_core_invoke_protocol_handler.
     * @retval true Operation was canceled.
     * @retval false Operation was already completed.
     */
    bool
    ebpf_core_cancel_protocol_handler(_Inout_ void* async_context);

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

    /**
     * @brief Return a handle to the object which is pinned at the
     *  supplied pin path.
     *
     * @param[in] path Path at which the object is pinned.
     * @param[out] handle Handle to the pinned object.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NOT_FOUND No object was pinned to the provided path.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_get_pinned_object(_In_ const ebpf_utf8_string_t* path, _Out_ ebpf_handle_t* handle);

    /**
     * @brief Pin or unpin an object to the provided path. If supplied handle is
     *  ebpf_handle_invalid, any object already pinned to the provided path is
     *  unpinned from the path.
     *
     * @param[in] handle Handle of the object to be pinned.
     * @param[in] path Pin path.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this operation.
     * @retval EBPF_NOT_FOUND No object was pinned to the provided path.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_update_pinning(const ebpf_handle_t handle, _In_ const ebpf_utf8_string_t* path);

    /**
     * @brief Create a new map object.
     *
     * @param[in] map_name Name of the map to be created.
     * @param[in] ebpf_map_definition Map definition structure.
     * @param[in] inner_map_handle Handle to the inner map object, if any.
     * @param[out] map_handle Handle to the created map object.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_create_map(
        _In_ const ebpf_utf8_string_t* map_name,
        _In_ const ebpf_map_definition_in_memory_t* ebpf_map_definition,
        ebpf_handle_t inner_map_handle,
        _Out_ ebpf_handle_t* map_handle);

    /**
     * @brief Load a block of eBPF code into the program instance.
     *
     * @param[in] program_handle Handle to the program object to load the eBPF code into.
     * @param[in] code_type Specifies whether eBPF code is JIT compiled, byte code or native code.
     * @param[in] code_context Optionally, pointer to code context.
     * @param[in] code Pointer to memory containing the eBPF code.
     * @param[in] code_size Size of the memory block containing the eBPF code.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_load_code(
        ebpf_handle_t program_handle,
        ebpf_code_type_t code_type,
        _In_opt_ const void* code_context,
        _In_reads_(code_size) const uint8_t* code,
        size_t code_size);

    /**
     * @brief Returns a handle to an object identified by the id.
     *
     * @param[in] type Type of the object to get handle of.
     * @param[in] id Specifies the ID of the object.
     * @param[out] handle Handle to the object.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_KEY_NOT_FOUND The provided ID is not valid.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_get_handle_by_id(ebpf_object_type_t type, ebpf_id_t id, _Out_ ebpf_handle_t* handle);

    /**
     * @brief Resolve the provided map handles to map addresses and associate the
     *  maps to the program object.
     *
     * @param[in] program_handle Handle of the program to associate maps with.
     * @param[in] count_of_maps Number of map handles.
     * @param[in] map_handles Array of map handles containing "count_of_maps" handles.
     * @param[out] map_addresses Array of map addresses of size "count_of_maps"
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_OBJECT The provided handle is not valid.
     * @retval EBPF_KEY_NOT_FOUND The provided ID is not valid.
     * @retval EBPF_INVALID_FD The program is incompatible with the map.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_resolve_maps(
        ebpf_handle_t program_handle,
        uint32_t count_of_maps,
        _In_reads_(count_of_maps) const ebpf_handle_t* map_handles,
        _Out_writes_(count_of_maps) uintptr_t* map_addresses);

    /**
     * @brief Resolve addresses for the provided helper function IDs and associate
     *  the helper IDs with the program object.
     *
     * @param[in] program_handle Handle of the program to associate maps with.
     * @param[in] count_of_helpers Number of helper function IDs.
     * @param[in] helper_function_ids Array of helper function IDs containing "count_of_helpers" IDs.
     * @param[out] helper_function_addresses Array of helper function addresses of size "count_of_helpers"
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_OBJECT The provided handle is not valid.
     * @retval EBPF_INVALID_ARGUMENT An invalid argument was supplied.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_resolve_helper(
        ebpf_handle_t program_handle,
        const size_t count_of_helpers,
        _In_reads_(count_of_helpers) const uint32_t* helper_function_ids,
        _Out_writes_(count_of_helpers) uint64_t* helper_function_addresses);

    /**
     * @brief Close the FsContext2 from a file object.
     *
     * @param[in] context The FsContext2 from a fileobject to close.
     */
    void
    ebpf_core_close_context(_In_opt_ void* context);

#ifdef __cplusplus
}
#endif
