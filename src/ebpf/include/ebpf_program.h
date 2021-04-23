/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include "ebpf_hook.h"
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
        ebpf_utf_8_t program_name;
        ebpf_utf_8_t section_name;
        ebpf_code_type_t code_type;
    } ebpf_program_parameters_t;

    typedef ebpf_error_code_t (*ebpf_program_entry_point_t)(void* context);

    /**
     * @brief Create a new program instance.
     *
     * @param[out] program Pointer to memory that will contain the program instance.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  program instance.
     */
    ebpf_error_code_t
    ebpf_program_create(ebpf_program_t** program);

    /**
     * @brief Initialize a program instance from the provided program
     *  parameters.
     *
     * @param[in] program Program instance to initialize.
     * @param[in] program_parameters Program parameters to be used to initialize
     *  the program instance.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  program instance.
     */
    ebpf_error_code_t
    ebpf_program_initialize(ebpf_program_t* program, const ebpf_program_parameters_t* program_parameters);

    /**
     * @brief Get properties describing the program instance.
     *
     * @param[in] program Program instance to query.
     * @param[in] program_parameters Parameters of the program.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  program instance.
     */
    ebpf_error_code_t
    ebpf_program_get_properties(ebpf_program_t* program, ebpf_program_parameters_t* program_parameters);

    /**
     * @brief Associate a set of maps with this program instance.
     *
     * @param[in] program Program instance to associate with the maps.
     * @param[in] maps Array of maps to associate with this program.
     * @param[in] maps_count Count of elements in the maps array.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  program instance.
     */
    ebpf_error_code_t
    ebpf_program_associate_maps(ebpf_program_t* program, ebpf_map_t** maps, size_t maps_count);

    /**
     * @brief Load a block of machine code into the program instance.
     *
     * @param[in] program Program instance to load the machine code into.
     * @param[in] machine_code Pointer to memory containing the machine code.
     * @param[in] machine_code_size Size of the memory block containing the machine
     *  code.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  program instance.
     */
    ebpf_error_code_t
    ebpf_program_load_machine_code(ebpf_program_t* program, uint8_t* machine_code, size_t machine_code_size);

    /**
     * @brief Load a block of eBPF instructions into the program instance.
     *
     * @param[in] program Program instance to load the byte code into.
     * @param[in] instructions Pointer to array of eBPF instructions.
     * @param[in] instruction_count Count of eBPF instructions to load.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  program instance.
     */
    ebpf_error_code_t
    ebpf_program_load_byte_code(ebpf_program_t* program, ebpf_instuction_t* instructions, size_t instruction_count);

    /**
     * @brief Create a hook instance and attach it to the program instance.
     *
     * @param[in] program Program instance to attach to.
     * @param[in] attach_type Attach type to load.
     * @param[in] context_data Data to be passed to the hook provider.
     * @param[in] context_data_length Length of the data to be passed to the
     *  hook provider.
     * @param[out] hook_instance The hook instance to initialize.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  program instance.
     */
    ebpf_error_code_t
    ebpf_program_create_and_attach_hook(
        ebpf_program_t* program,
        ebpf_attach_type_t attach_type,
        uint8_t* context_data,
        size_t context_data_length,
        ebpf_hook_instance_t** hook_instance);

    /**
     * @brief Attach this program instance to an existing hook instance.
     *
     * @param[in] program Program instance to attach to.
     * @param[in] hook_instance Hook instance to attach the program instance to.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  program instance.
     */
    ebpf_error_code_t
    ebpf_program_attach_hook(ebpf_program_t* program, ebpf_hook_instance_t* hook_instance);

    /**
     * @brief Obtain the entry point for the program instance. Only applicable
     *  to when program instance has machine code loaded.
     *
     * @param[in] program Program instance to retrieve entry point from.
     * @param[out] program_entry_point Entry point for the machine code.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     */
    ebpf_error_code_t
    ebpf_program_get_entry_point(ebpf_program_t* program, ebpf_program_entry_point_t* program_entry_point);

    /**
     * @brief Invoke an ebpf_program_t instance.
     *
     * @param[in] program Program to invoke.
     * @param[in] context Pointer to eBPF context for this program.
     * @param[out] result Output from the program.
     */
    void
    ebpf_program_invoke(ebpf_program_t* program, void* context, uint32_t* result);

#ifdef __cplusplus
}
#endif
