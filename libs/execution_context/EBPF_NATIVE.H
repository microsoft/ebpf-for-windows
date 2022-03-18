// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_core_structs.h"
#include "ebpf_maps.h"
// #include "ebpf_platform.h"
#include "bpf2c.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef struct _ebpf_native ebpf_native_t;

    // typedef program_entry_t ebpf_native_program_t;
    // typedef helper_function_entry_t ebpf_native_helper_entry_t;
    // typedef map_entry_t ebpf_native_map_t;

    /**
     * @brief Initialize the eBPF native code module.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_native_initiate();

    /**
     * @brief Uninitialize the eBPF native code module.
     *
     */
    void
    ebpf_native_terminate();

    /**
     * @brief Load driver and bind to the native module.
     *
     * @param[in] service_name Name of the service for the native module.
     * @param[in] service_name_length Length of service_name.
     * @param[in] module_id Identifier of the native eBPF module to load.
     * @param[out] count_of_maps Count of maps in the native module.
     * @param[out] count_of_programs Count of programs in the native module.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     * @retval EBPF_OBJECT_NOT_FOUND No native program exists with that module ID.
     * @retval EBPF_OBJECT_ALREADY_EXISTS Native module for this module ID is already
     *  initialized.
     */
    ebpf_result_t
    ebpf_native_load(
        _In_ const wchar_t* service_name,
        uint16_t service_name_length,
        _In_ const GUID* module_id,
        _Out_ size_t* count_of_maps,
        _Out_ size_t* count_of_programs);

    /**
     * @brief Load programs, create maps and resolve map and helper addresses for
     *  already loaded native module.
     *
     * @param[in] module_id Identifier of the native eBPF module to load programs
     *  and maps from.
     * @param[in] count_of_map_handles Count of maps in this module.
     * @param[out] map_handles Array of handles of the maps created.
     * @param[in] count_of_program_handles Count of programs in the native module.
     * @param[out] program_handles Array of handles for the programs created.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     * @retval EBPF_OBJECT_NOT_FOUND No native program exists with that module ID.
     * @retval EBPF_OBJECT_ALREADY_EXISTS Native module for this module ID is already
     *  initialized.
     */
    ebpf_result_t
    ebpf_native_load_programs(
        _In_ const GUID* module_id,
        size_t count_of_map_handles,
        _Out_writes_(count_of_map_handles) ebpf_handle_t* map_handles,
        size_t count_of_program_handles,
        _Out_writes_(count_of_program_handles) ebpf_handle_t* program_handles);

    /**
     * @brief Get count of programs in the native module.
     *
     * @param[in] module_id Pointer to module id.
     * @param[out] count_of_maps Count of programs.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_OBJECT_NOT_FOUND Specified module was not found.
     */
    ebpf_result_t
    ebpf_native_get_count_of_programs(_In_ const GUID* module_id, _Out_ size_t* count_of_programs);

    /**
     * @brief Get count of maps in the native module.
     *
     * @param[in] module_id Pointer to module id.
     * @param[out] count_of_maps Count of maps.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_OBJECT_NOT_FOUND Specified module was not found.
     */
    ebpf_result_t
    ebpf_native_get_count_of_maps(_In_ const GUID* module_id, _Out_ size_t* count_of_maps);

    /**
     * @brief Unload driver for the specified module id.
     *
     * @param[in] module_id Pointer to module id whose driver is to be unloaded.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate memory for service name.
     */
    ebpf_result_t
    ebpf_native_unload(_In_ const GUID* module_id);

    /**
     * @brief Get a list of maps associated with the eBPF program.
     *
     * @param[in] native The object tracking the native eBPF code.
     * @param[out] maps List of maps to associated with the native eBPF code.
     * @param[out] count_of_maps Count of maps in returned map list.
     */
    // void ebpf_native_get_maps(_In_ const ebpf_native_t* native, _Out_ ebpf_native_map_t** maps, _Out_ size_t*
    // count_of_maps);

    /**
     * @brief Retrieve a pointer to the native eBPF program code block.
     *
     * @param[in] native The object tracking the native eBPF code.
     * @param[in] name Name of the eBPF native code block to retrieve.
     * @param[out] program Pointer to the program code block.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_OBJECT_NOT_FOUND No native program exists with that name.
     */
    // ebpf_result_t ebpf_native_get_programs(_In_ ebpf_native_t* native, _Out_ ebpf_native_program_t** programs, _Out_
    // size_t* count_of_programs);

    // ebpf_result_t ebpf_native_get_helpers(_In_ ebpf_native_t* native, _Out_ ebpf_native_program_t** programs, _Out_
    // size_t* count_of_programs);

    /**
     * @brief Retrieve information about the eBPF program code block.
     *
     * @param[in] native The object tracking the native eBPF code.
     * @param[in] name Name of the eBPF native code block to retrieve.
     * @param[out] program_type Type of the native eBPF code.
     * @param[out] program_name Function name of the native eBPF code.
     * @param[out] section_name Section name of the native eBPF code.
     * @param[out] file_name Original ELF file name.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_OBJECT_NOT_FOUND No native program exists with that name.
     */
    /*
    ebpf_result_t
        ebpf_native_get_program_information(
            _In_ ebpf_native_t* native,
            _In_ ebpf_utf8_string_t* name,
            _Out_ ebpf_program_type_t* program_type,
            _Out_ ebpf_utf8_string_t* program_name,
            _Out_ ebpf_utf8_string_t* section_name,
            _Out_ ebpf_utf8_string_t* file_name);
    */

    void
    ebpf_native_acquire_reference(ebpf_native_t* native);

    void
    ebpf_native_release_reference(ebpf_native_t* native);

#ifdef __cplusplus
}
#endif
