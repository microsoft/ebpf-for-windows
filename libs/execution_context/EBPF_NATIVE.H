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
     * @brief Load and bind to native eBPF code and optionally re-use existing maps. Caller is responsible for calling
     * ebpf_object_release_reference when they no longer need this object.
     *
     * @param[in] module_id Identifier of the native eBPF code to load.
     * @param[out] native Pointer to the object tracking the native eBPF code.
     * @param[in] maps List of maps to re-use with the native eBPF code.
     * @param[in] count_of_maps Count of maps in maps list.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     * @retval EBPF_OBJECT_NOT_FOUND No native program exists with that module ID.
     */
    ebpf_result_t
    ebpf_native_load(
        _In_ const wchar_t* service_name,
        uint16_t service_name_length,
        _In_ const GUID* module_id,
        _Out_ size_t* count_of_maps,
        _Out_ size_t* count_of_programs);

    ebpf_result_t
    ebpf_native_load_programs(
        _In_ const GUID* module_id,
        _Out_ size_t* count_of_map_handles,
        _Out_ ebpf_handle_t** map_handles,
        _Out_ size_t* count_of_program_handles,
        _Out_ ebpf_handle_t** program_handles);

    ebpf_result_t
    ebpf_native_get_count_of_programs(_In_ const GUID* module_id, _Out_ size_t* count_of_programs);

    ebpf_result_t
    ebpf_native_get_count_of_maps(_In_ const GUID* module_id, _Out_ size_t* count_of_maps);

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
