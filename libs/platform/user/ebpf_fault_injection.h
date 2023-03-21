// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Initialize fault injection.  This must be called before any other
     * fault injection functions. This function is not thread safe.
     *
     * @param[in] stack_depth Number of stack frames to capture when a fault is
     * injected.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Operation failed due to memory allocation failure.
     */
    ebpf_result_t
    ebpf_fault_injection_initialize(size_t stack_depth) noexcept;

    /**
     * @brief Uninitialize fault injection. This must be called after all other
     * fault injection functions. This function is not thread safe.
     */
    void
    ebpf_fault_injection_uninitialize() noexcept;

    /**
     * @brief Enable fault injection. This function is thread safe.
     *
     * @retval true Fault should be injected.
     * @retval false Fault should not be injected.
     */
    bool
    ebpf_fault_injection_inject_fault() noexcept;

    /**
     * @brief Test if fault injection is enabled. This function is thread safe.
     *
     * @retval true Fault injection is enabled.
     * @retval false Fault injection is disabled.
     */
    bool
    ebpf_fault_injection_is_enabled() noexcept;

#ifdef __cplusplus
}
#endif
