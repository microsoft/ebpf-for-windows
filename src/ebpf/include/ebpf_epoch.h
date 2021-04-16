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

    ebpf_error_code_t
    ebpf_epoch_initialize();

    void
    ebpf_epoch_terminate();

    /**
     * @brief Called prior to touching memory with lifetime under epoch control.
     */
    ebpf_error_code_t
    ebpf_epoch_enter();

    /**
     * @brief Called after touching memory with lifetime under epoch control.
     */
    void
    ebpf_epoch_exit();

    /**
     * @brief Allocate memory under epoch control.
     * @param[in] size Size of memory to allocate
     * @param[in] type Allocate memory as executable vs non-executable
     */
    void*
    ebpf_epoch_allocate(size_t size, ebpf_memory_type_t type);

    /**
     * @brief Free memory under epoch control.
     * @param[in] memory Allocation to be freed once epoch ends.
     */
    void
    ebpf_epoch_free(void* memory);

    /**
     * @Brief Release any memory that is associated with expired epochs.
     */
    void
    ebpf_epoch_flush();

#ifdef __cplusplus
}
#endif
