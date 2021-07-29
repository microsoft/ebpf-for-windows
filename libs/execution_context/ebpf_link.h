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
    typedef struct _ebpf_program ebpf_program_t;

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

    /**
     * @brief Detach a program from this link object.
     *
     * @param[in] entry List entry corresponding to the link object.
     */
    void
    ebpf_link_entry_detach_program(_Inout_ ebpf_list_entry_t* entry);

    /**
     * @brief Insert link object to the tail of provided attach list head.
     *
     * @param[in] head Head of the attach list.
     * @param[in] link Link to be inserted in the list.
     */
    void
    ebpf_link_insert_to_attach_list(_Inout_ ebpf_list_entry_t* head, _Inout_ ebpf_link_t* link);

    /**
     * @brief Remove link object from the attach list.
     *
     * @param[in] link Link to be removed from the attach list.
     */
    void
    ebpf_link_remove_from_attach_list(_Inout_ ebpf_link_t* link);

#ifdef __cplusplus
}
#endif
