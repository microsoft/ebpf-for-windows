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
    } ebpf_program_parameters_t;

    typedef ebpf_result_t (*ebpf_program_entry_point_t)(void* context);

    /**
     * @brief Initialize global state for the ebpf program module.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
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
    ebpf_result_t
    ebpf_program_create(_Outptr_ ebpf_program_t** program);

    /**
     * @brief Initialize a program instance from the provided program
     *  parameters.
     *
     * @param[in,out] program Program instance to initialize.
     * @param[in] program_parameters Program parameters to be used to initialize
     *  the program instance.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    ebpf_result_t
    ebpf_program_initialize(_Inout_ ebpf_program_t* program, _In_ const ebpf_program_parameters_t* program_parameters);

    /**
     * @brief Get parameters describing the program instance.
     *
     * @param[in] program Program instance to query.
     * @returns Pointer to parameters of the program.
     */
    _Ret_notnull_ const ebpf_program_parameters_t*
    ebpf_program_get_parameters(_In_ const ebpf_program_t* program);

    _Ret_notnull_ const ebpf_program_type_t*
    ebpf_program_type_uuid(_In_ const ebpf_program_t* program);

    _Ret_notnull_ const ebpf_attach_type_t*
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
    ebpf_result_t
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
    ebpf_result_t
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
    ebpf_result_t
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
    ebpf_result_t
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
     * @param[in] context Pointer to eBPF context for this program.
     * @param[out] result Output from the program.
     */
    void
    ebpf_program_invoke(_In_ const ebpf_program_t* program, _In_ void* context, _Out_ uint32_t* result);

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
    ebpf_result_t
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
    ebpf_result_t
    ebpf_program_get_helper_function_addresses(
        _In_ const ebpf_program_t* program,
        const size_t addresses_count,
        _Out_writes_(addresses_count) uint64_t* addresses);

    /**
     * @brief Attach a link object to an eBPF program.
     *
     * @param[in] program Program to attach to the link object.
     * @param[in] link The link object.
     */
    void
    ebpf_program_attach_link(_Inout_ ebpf_program_t* program, _Inout_ ebpf_link_t* link);

    /**
     * @brief Detach a link object from the eBPF program it is attached to.
     *
     * @param[in] program Program to detach to the link object from.
     * @param[in] link The link object.
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
    ebpf_result_t
    ebpf_program_set_tail_call(_In_ const ebpf_program_t* next_program);

    /**
     * @brief Get bpf_prog_info about a program.
     *
     * @param[in] program The program to get info about.
     * @param[in] input_buffer Buffer to read bpf_prog_info from.
     * @param[out] output_buffer Buffer to write bpf_prog_info into.
     * @param[in,out] info_size On input, the size in bytes of the buffer.
     * On output, the number of bytes actually written.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INSUFFICIENT_BUFFER The buffer was too small to hold bpf_prog_info.
     */
    ebpf_result_t
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
    ebpf_result_t
    ebpf_program_create_and_initialize(
        _In_ const ebpf_program_parameters_t* parameters, _Out_ ebpf_handle_t* program_handle);

#ifdef __cplusplus
}
#endif
