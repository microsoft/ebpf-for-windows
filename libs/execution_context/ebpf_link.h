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
     * @param[in] attach_type Attach type to load.
     * @param[in] context_data Data to be passed to the hook provider.
     * @param[in] context_data_length Length of the data to be passed to the hook
     * @param[out] link Pointer to memory that will contain the link object
     *  on success.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  link object.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_link_create(
        ebpf_attach_type_t attach_type,
        _In_reads_(context_data_length) const uint8_t* context_data,
        size_t context_data_length,
        _Outptr_ ebpf_link_t** link);

    /**
     * @brief Attach a program to this link object.
     *
     * @param[in, out] link The link object to attach the program to.
     * @param[in, out] program The program to attach to this link object.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT Hook instance has not been
     *  initialized.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_link_attach_program(_Inout_ ebpf_link_t* link, _Inout_ ebpf_program_t* program);

    /**
     * @brief Detach a program from this link object.
     *
     * @param[in] link The link object to detach.
     */
    void
    ebpf_link_detach_program(_Inout_ ebpf_link_t* link);

    /**
     * @brief Get bpf_link_info about a link.
     *
     * @param[in] link The link object to get info about.
     * @param[out] buffer Buffer to write bpf_link_info into.
     * @param[in, out] info_size On input, the size in bytes of the buffer.
     * On output, the number of bytes actually written.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INSUFFICIENT_BUFFER The buffer was too small to hold bpf_link_info.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_link_get_info(
        _In_ const ebpf_link_t* link,
        _Out_writes_to_(*info_size, *info_size) uint8_t* buffer,
        _Inout_ uint16_t* info_size);

#ifdef __cplusplus
}
#endif
