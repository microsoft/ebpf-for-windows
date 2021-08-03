// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef GUID ebpf_attach_type_t;
    typedef struct _ebpf_link ebpf_link_t;
    typedef struct bpf_program ebpf_program_t;

    /**
     * @brief Create a new link object.
     *
     * @param[out] link Pointer to memory that will contain the link object
     *  on success.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  link object.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    ebpf_result_t
    ebpf_link_create(ebpf_link_t** link);

    /**
     * @brief Initialize this link object and load the associated hook
     *  provider if needed.
     *
     * @param[in] link The link object to initialize.
     * @param[in] attach_type Attach type to load.
     * @param[in] context_data Data to be passed to the hook provider.
     * @param[in] context_data_length Length of the data to be passed to the hook
     *  provider.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    ebpf_result_t
    ebpf_link_initialize(
        ebpf_link_t* link, ebpf_attach_type_t attach_type, const uint8_t* context_data, size_t context_data_length);

    /**
     * @brief Attach a program to this link object.
     *
     * @param[in] link The link object to attach the program to.
     * @param[in] program The program to attach to this link object.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT Hook instance has not been
     *  initialized.
     */
    ebpf_result_t
    ebpf_link_attach_program(ebpf_link_t* link, ebpf_program_t* program);

    /**
     * @brief Detach a program from this link object.
     *
     * @param[in] link The link object to detach.
     */
    void
    ebpf_link_detach_program(ebpf_link_t* link);

#ifdef __cplusplus
}
#endif
