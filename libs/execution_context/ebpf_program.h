// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_link.h"
#include "ebpf_maps.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_protocol.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef enum _ebpf_code_type ebpf_code_type_t;

    typedef struct _ebpf_instruction
    {
        uint8_t opcode;
        uint8_t dst : 4; //< Destination register
        uint8_t src : 4; //< Source register
        int16_t offset;
        int32_t imm; //< Immediate constant
    } ebpf_instruction_t;

    typedef struct _ebpf_program_parameters
    {
        ebpf_program_type_t program_type;
        ebpf_attach_type_t expected_attach_type;
        ebpf_utf8_string_t program_name;
        ebpf_utf8_string_t section_name;
        ebpf_utf8_string_t file_name;
        ebpf_code_type_t code_type;
        const uint8_t* program_info_hash;
        size_t program_info_hash_length;
    } ebpf_program_parameters_t;

    typedef ebpf_result_t (*ebpf_program_entry_point_t)(void* context);

    /**
     * @brief Initialize global state for the ebpf program module.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_initiate();

    /**
     * @brief Uninitialize the eBPF state tracking module.
     *
     */
    void
    ebpf_program_terminate();

    /**
     * @brief Create a new program instance.
     *
     * @param[out] program Pointer to memory that will contain the program instance.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_create(_Outptr_ ebpf_program_t** program);

    /**
     * @brief Initialize a program instance from the provided program
     *  parameters.
     *
     * @param[in, out] program Program instance to initialize.
     * @param[in] program_parameters Program parameters to be used to initialize
     *  the program instance.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_initialize(_Inout_ ebpf_program_t* program, _In_ const ebpf_program_parameters_t* program_parameters);

    /**
     * @brief Get the original file name of the program.
     *
     * @param[in] program The program instance.
     * @param[out] file_name The file name of the program. Caller must free this.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_get_program_file_name(_In_ const ebpf_program_t* program, _Out_ ebpf_utf8_string_t* file_name);

    /**
     * @brief Get the original section name of the program.
     *
     * @param[in] program The program instance.
     * @param[out] section_name The section name of the program. Caller must free this.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_get_program_section_name(_In_ const ebpf_program_t* program, _Out_ ebpf_utf8_string_t* section_name);

    /**
     * @brief Get the code type of the program.
     *
     * @param[in] program The program instance.
     * @return The code type of the program.
     */
    ebpf_code_type_t
    ebpf_program_get_code_type(_In_ const ebpf_program_t* program);

    ebpf_program_type_t
    ebpf_program_type_uuid(_In_ const ebpf_program_t* program);

    ebpf_attach_type_t
    ebpf_expected_attach_type(_In_ const ebpf_program_t* program);

    /**
     * @brief Get the program info from the program info extension.
     *
     * @param[in] program Program that loaded the extension.
     * @param[out] program_info Pointer to the output allocated program info. Must be freed by caller by calling
     * ebpf_program_free_program_info().
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT One or more arguments are invalid.
     * @retval EBPF_ARITHMETIC_OVERFLOW An arithmetic overflow has occurred.
     * @retval EBPF_NO_MEMORY Output program info could not be allocated.
     * @retval EBPF_ERROR_EXTENSION_FAILED_TO_LOAD The program info isn't
     *  available.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_get_program_info(_In_ const ebpf_program_t* program, _Outptr_ ebpf_program_info_t** program_info);

    /**
     * @brief Free the program info allocated by ebpf_program_get_program_info().
     *
     * @param[in] program_info Program info to be freed.
     */
    void
    ebpf_program_free_program_info(_In_opt_ _Post_invalid_ ebpf_program_info_t* program_info);

    /**
     * @brief Associate a set of maps with this program instance.
     *
     * @param[in] program Program instance to associate with the maps.
     * @param[in] maps Array of maps to associate with this program.
     * @param[in] maps_count Count of elements in the maps array.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_associate_maps(ebpf_program_t* program, ebpf_map_t** maps, uint32_t maps_count);

    /**
     * @brief Associate an additional map with this program instance.
     *
     * @param[in] program Program instance to associate with the map.
     * @param[in] map Map to associate with this program.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_associate_additional_map(ebpf_program_t* program, ebpf_map_t* map);

    /**
     * @brief Load a block of eBPF code into the program instance.
     *
     * @param[in, out] program Program instance to load the eBPF code into.
     * @param[in] code_type Specifies whether eBPF code is JIT compiled or byte code.
     * @param[in] code_context Optionally, pointer to code context.
     * @param[in] code Pointer to memory containing the eBPF code.
     * @param[in] code_size Size of the memory block containing the eBPF
     *  code.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_load_code(
        _Inout_ ebpf_program_t* program,
        ebpf_code_type_t code_type,
        _In_opt_ const void* code_context,
        _In_reads_(code_size) const uint8_t* code,
        size_t code_size);

    /**
     * @brief Invoke an ebpf_program_t instance.
     *
     * @param[in] program Program to invoke.
     * @param[in,out] context Pointer to eBPF context for this program.
     * @param[out] result Output from the program.
     * @param[in] execution_state Execution context state.
     */
    void
    ebpf_program_invoke(
        _In_ const ebpf_program_t* program,
        _Inout_ void* context,
        _Out_ uint32_t* result,
        _In_ const ebpf_execution_context_state_t* execution_state);

    /**
     * @brief Store the helper function IDs that are used by the eBPF program in an array
     *  inside the program object. The array index is the helper function ID to be used by
     *  uBPF whereas the array value is the actual helper ID.
     *
     * @param[in, out] program Program object to query this on.
     * @param[in] helper_function_count Count of helper functions.
     * @param[in] helper_function_ids Array of helper function IDs to store.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT The helper function IDs array is already populated.
     * @retval EBPF_NO_MEMORY Could not allocate array of helper function IDs.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_set_helper_function_ids(
        _Inout_ ebpf_program_t* program,
        const size_t helper_function_count,
        _In_reads_(helper_function_count) const uint32_t* helper_function_ids);

    /**
     * @brief Get the addresses of helper functions referred to by the program. Assumes
     * ebpf_program_set_helper_function_ids has already been invoked on the program object.
     *
     * @param[in] program Program object to query this on.
     * @param[in] addresses_count Length of caller supplied output array.
     * @param[out] address Caller supplied output array where the addresses of the helper functions are written to.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INSUFFICIENT_BUFFER Output array is insufficient.
     * @retval EBPF_INVALID_ARGUMENT At least one helper function id is not valid.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_get_helper_function_addresses(
        _In_ const ebpf_program_t* program,
        const size_t addresses_count,
        _Out_writes_(addresses_count) uint64_t* addresses);

    /**
     * @brief Attach a link object to an eBPF program.
     *
     * @param[in, out] program Program to attach to the link object.
     * @param[in, out] link The link object.
     */
    void
    ebpf_program_attach_link(_Inout_ ebpf_program_t* program, _Inout_ ebpf_link_t* link);

    /**
     * @brief Detach a link object from the eBPF program it is attached to.
     *
     * @param[in, out] program Program to detach to the link object from.
     * @param[in, out] link The link object.
     */
    void
    ebpf_program_detach_link(_Inout_ ebpf_program_t* program, _Inout_ ebpf_link_t* link);

    /**
     * @brief Store the pointer to the program to execute on tail call.
     *
     * @param[in] next_program Next program to execute.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT Internal error.
     * @retval EBPF_NO_MORE_TAIL_CALLS Program has executed to many tail calls.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_set_tail_call(_In_ const ebpf_program_t* next_program);

    /**
     * @brief Get bpf_prog_info about a program.
     *
     * @param[in] program The program to get info about.
     * @param[in] input_buffer Buffer to read bpf_prog_info from.
     * @param[out] output_buffer Buffer to write bpf_prog_info into.
     * @param[in, out] info_size On input, the size in bytes of the buffer.
     * On output, the number of bytes actually written.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INSUFFICIENT_BUFFER The buffer was too small to hold bpf_prog_info.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_get_info(
        _In_ const ebpf_program_t* program,
        _In_reads_(*info_size) const uint8_t* input_buffer,
        _Out_writes_to_(*info_size, *info_size) uint8_t* output_buffer,
        _Inout_ uint16_t* info_size);

    /**
     * @brief Create a new program instance and initialize the instance from
     *  the provided program parameters.
     *
     * @param[in] parameters Program parameters to be used to initialize
     *  the program instance.
     * @param[out] program_handle Handle to the created program instance.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_create_and_initialize(
        _In_ const ebpf_program_parameters_t* parameters, _Out_ ebpf_handle_t* program_handle);

    typedef struct _ebpf_program_test_run_options
    {
        _Readable_bytes_(data_size_in) const uint8_t* data_in; ///< Input data to the program.
        _Writable_bytes_(data_size_out) uint8_t* data_out;     ///< Output data from the program.
        size_t data_size_in;                                   ///< Size of input data.
        size_t data_size_out; ///< Maximum length of data_out on input and actual length of data_out on output.
        _Readable_bytes_(context_size_in) const uint8_t* context_in; ///< Input context to the program.
        _Writable_bytes_(context_size_out) uint8_t* context_out;     ///< Output context from the program.
        size_t context_size_in;                                      ///< Size of input context.
        size_t context_size_out; ///< Maximum length of context_out on input and actual length of context_out on output.
        uint64_t return_value;   ///< Return value from the program.
        size_t repeat_count;     ///< Number of times to repeat the program.
        uint64_t duration;       ///< Duration in nanoseconds of the program execution.
        uint32_t flags;          ///< Flags to control the test run.
        uint32_t cpu;            ///< CPU to run the program on.
        size_t batch_size;       ///< Number of times to repeat the program in a batch.
    } ebpf_program_test_run_options_t;

    /**
     * @brief Function called when the program test run completes.
     *
     */
    typedef void (*ebpf_program_test_run_complete_callback_t)(
        _In_ ebpf_result_t result,
        _In_ const ebpf_program_t* program,
        _In_ const ebpf_program_test_run_options_t* options,
        _Inout_ void* completion_context,
        _Inout_ void* async_context);

    /**
     * @brief Run the program with the given input and output buffers and measure the duration.
     *
     * @param[in] program Program to run.
     * @param[in, out] options Options to control the test run.
     * @param[in] async_context Async context to receive cancellation notifications on.
     * @param[in] completion_context Context to pass to the completion callback.
     * @param[in] callback Completion callback.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT Invalid argument.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this program.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_execute_test_run(
        _In_ const ebpf_program_t* program,
        _Inout_ ebpf_program_test_run_options_t* options,
        _In_ void* async_context,
        _In_ void* completion_context,
        _In_ ebpf_program_test_run_complete_callback_t callback);

    typedef ebpf_result_t (*ebpf_helper_function_addresses_changed_callback_t)(
        _Inout_ ebpf_program_t* program, _In_opt_ void* context);

    /**
     * @brief Register to be notified when the helper function addresses change.
     *
     * @param[in,out] program Program to register for helper function address changes.
     * @param[in] callback Function to call when helper function addresses change.
     * @param[in] context Context to pass to the callback.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT Invalid argument.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_register_for_helper_changes(
        _Inout_ ebpf_program_t* program,
        _In_ ebpf_helper_function_addresses_changed_callback_t callback,
        _In_opt_ void* context);

    /**
     * @brief Acquire a reference to the program information provider.
     *
     * @param[in,out] program Program to acquire a reference to the provider for.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_EXTENSION_FAILED_TO_LOAD The provider failed to load.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_program_reference_providers(_Inout_ ebpf_program_t* program);

    /**
     * @brief Release a reference to the program information provider.
     *
     * @param[in,out] program Program to release a reference to the provider for.
     */
    void
    ebpf_program_dereference_providers(_Inout_ ebpf_program_t* program);

#ifdef __cplusplus
}
#endif
