/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include "ebpf_platform.h"
#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct _ebpf_program ebpf_program_t;
    typedef ebpf_error_code_t (*ebpf_program_entry_point)(void* context);

    /**
     * @brief Acquire a reference on this program.
     *
     * @param[in] program Program to acquire reference on.
     */
    void
    ebpf_program_acquire_reference(ebpf_program_t* program);

    /**
     * @brief Release a reference on this program.
     *
     * @param[in] program Program instance to release reference on.
     */
    void
    ebpf_program_release_reference(ebpf_program_t* program);

    /**
     * @brief Get the entry point from this program object.
     *
     * @param[in] program Program object that contain the entry point.
     * @param[out] program_entry_point Entry point for the program.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     */
    ebpf_error_code_t
    ebpf_program_get_entry_point(ebpf_program_t* program, ebpf_program_entry_point* program_entry_point);

#ifdef __cplusplus
}
#endif
