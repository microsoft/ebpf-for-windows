// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_link.h"
#include "ebpf_maps.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef enum _ebpf_code_type ebpf_code_type_t;

    typedef struct _ebpf_instuction
    {
        uint8_t opcode;
        uint8_t dst : 4; //< Destination register
        uint8_t src : 4; //< Source register
        int16_t offset;
        int32_t imm; //< Immediate constant
    } ebpf_instuction_t;

    typedef struct _ebpf_program ebpf_program_t;
    typedef struct _ebpf_program_parameters
    {
        ebpf_program_type_t program_type;
        ebpf_utf8_string_t program_name;
        ebpf_utf8_string_t section_name;
        ebpf_code_type_t code_type;
    } ebpf_program_parameters_t;

    typedef ebpf_result_t (*ebpf_program_entry_point_t)(void* context);

    /**
     * @brief Create a new program instance.
     *
     * @param[out] program Pointer to memory that will contain the program instance.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    ebpf_result_t
    ebpf_program_create(ebpf_program_t** program);

    /**
     * @brief Initialize a program instance from the provided program
     *  parameters.
     *
     * @param[in] program Program instance to initialize.
     * @param[in] program_parameters Program parameters to be used to initialize
     *  the program instance.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    ebpf_result_t
    ebpf_program_initialize(ebpf_program_t* program, const ebpf_program_parameters_t* program_parameters);

    /**
     * @brief Get properties describing the program instance.
     *
     * @param[in] program Program instance to query.
     * @param[in] program_parameters Parameters of the program.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    ebpf_result_t
    ebpf_program_get_properties(ebpf_program_t* program, ebpf_program_parameters_t* program_parameters);

    /**
     * @brief Get the program info data from the program info
     *  extension.
     *
     * @param[in] program Program that loaded the extension.
     * @param[out] program_info_data Pointer to the program info.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_EXTENSION_FAILED_TO_LOAD The program info isn't
     *  available.
     */
    ebpf_result_t
    ebpf_program_get_program_info_data(const ebpf_program_t* program, const ebpf_extension_data_t** program_info_data);

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
    ebpf_program_associate_maps(ebpf_program_t* program, ebpf_map_t** maps, size_t maps_count);

    /**
     * @brief Load a block of machine code into the program instance.
     *
     * @param[in] program Program instance to load the machine code into.
     * @param[in] machine_code Pointer to memory containing the machine code.
     * @param[in] machine_code_size Size of the memory block containing the machine
     *  code.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    ebpf_result_t
    ebpf_program_load_machine_code(ebpf_program_t* program, uint8_t* machine_code, size_t machine_code_size);

    /**
     * @brief Load a block of eBPF instructions into the program instance.
     *
     * @param[in] program Program instance to load the byte code into.
     * @param[in] instructions Pointer to array of eBPF instructions.
     * @param[in] instruction_count Count of eBPF instructions to load.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  program instance.
     */
    ebpf_result_t
    ebpf_program_load_byte_code(ebpf_program_t* program, ebpf_instuction_t* instructions, size_t instruction_count);

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
     * @brief Get the address of a helper function.
     *
     * @param[in] program Program object to query this on.
     * @param[in] helper_function_id Helper function ID to look up.
     * @param[out] address Address of the helper function.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT The helper_function_id is not valid.
     */
    ebpf_result_t
    ebpf_program_get_helper_function_address(
        const ebpf_program_t* program, uint32_t helper_function_id, uint64_t* address);

#ifdef __cplusplus
}
#endif
