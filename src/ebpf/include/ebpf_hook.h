/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include "ebpf_platform.h"
#include "ebpf_program.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef GUID ebpf_attach_type_t;
    typedef struct _ebpf_hook_instance ebpf_hook_instance_t;

    /**
     * @brief Create a new hook instance.
     *
     * @param[out] hook_instance Pointer to memory that will contain the hook instance
     *  on success.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  hook instance.
     */
    ebpf_error_code_t
    ebpf_hook_instance_create(ebpf_hook_instance_t** hook_instance);

    /**
     * @brief Initialize this hook instance and load the associated hook
     *  provider if needed.
     *
     * @param[in] hook_instance The hook instance to initialize.
     * @param[in] attach_type Attach type to load.
     * @param[in] context_data Data to be passed to the hook provider.
     * @param[in] context_data_length Length of the data to be passed to the hook
     *  provider.
     * @return ebpf_error_code_t TBD
     */
    ebpf_error_code_t
    ebpf_hook_instance_initialize(
        ebpf_hook_instance_t* hook_instance,
        ebpf_attach_type_t attach_type,
        uint8_t* context_data,
        size_t context_data_length);

    /**
     * @brief Get the properties from the hook provider.
     *
     * @param[in] hook_instance The hook instance to get properties from.
     * @param[out] hook_properties Pointer to buffer that contains the hook
     *  provider properties on success.
     * @param[out] hook_properties_length Pointer to size that contains the size
     *  of the hook provider properties.
     * @retval EBPF_ERROR_INVALID_PARAMETER Hook instance has not been
     *  initialzed.
     */
    ebpf_error_code_t
    ebpf_hook_instance_get_properties(
        ebpf_hook_instance_t* hook_instance, uint8_t** hook_properties, size_t* hook_properties_length);

    /**
     * @brief Attach a program to this hook instance.
     *
     * @param hook_instance The hook instance to attach the program to.
     * @param program The program to attach to this hook instance.
     * @retval EBPF_ERROR_INVALID_PARAMETER Hook instance has not been
     *  initialzed.
     */
    ebpf_error_code_t
    ebpf_hook_instance_attach_program(ebpf_hook_instance_t* hook_instance, ebpf_program_t* program);

    /**
     * @brief Detach a program from this hook instance.
     *
     * @param hook_instance The hook instance to detach from.
     */
    void
    ebpf_hook_instance_detach_program(ebpf_hook_instance_t* hook_instance);

    /**
     * @brief Acquire a reference on this hook instance.
     *
     * @param[in] hook_instance Hook instance to acquire reference on.
     */
    void
    ebpf_hook_instance_acquire_reference(ebpf_hook_instance_t* hook_instance);

    /**
     * @brief Release a reference on this hook instance.
     *
     * @param[in] hook_instance Hook instance to release reference on.
     */
    void
    ebpf_hook_instance_release_reference(ebpf_hook_instance_t* hook_instance);

#ifdef __cplusplus
}
#endif
