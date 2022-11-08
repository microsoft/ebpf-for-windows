// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_core_structs.h"
#include "ebpf_maps.h"
#include "bpf2c.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef struct _ebpf_native_module ebpf_native_module_binding_context_t;

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
     * @brief Load native module driver and bind to the native module.
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
     * @retval EBPF_OBJECT_NOT_FOUND Native module for that module ID not found.
     * @retval EBPF_OBJECT_ALREADY_EXISTS Native module for this module ID is already
     *  initialized.
     */
    ebpf_result_t
    ebpf_native_load(
        _In_reads_(service_name_length) const wchar_t* service_name,
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
     * @param[in] count_of_map_handles Count of maps in the native module.
     * @param[out] map_handles Array of handles of the maps created.
     * @param[in] count_of_program_handles Count of programs in the native module.
     * @param[out] program_handles Array of handles for the programs created.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     * @retval EBPF_OBJECT_NOT_FOUND No native module exists with that module ID.
     * @retval EBPF_OBJECT_ALREADY_EXISTS Native module for this module ID is already
     *  loaded.
     */
    ebpf_result_t
    ebpf_native_load_programs(
        _In_ const GUID* module_id,
        size_t count_of_map_handles,
        _Out_writes_opt_(count_of_map_handles) ebpf_handle_t* map_handles,
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
     * @brief Acquire reference on the native module.
     *
     * @param[inout] module Pointer to native module.
     */
    void
    ebpf_native_acquire_reference(_Inout_ ebpf_native_module_binding_context_t* module);

    /**
     * @brief Release reference to the native module.
     *
     * @param[in] module Optionally, pointer to native module.
     */
    void
    ebpf_native_release_reference(_In_opt_ ebpf_native_module_binding_context_t* module);

#ifdef __cplusplus
}
#endif
