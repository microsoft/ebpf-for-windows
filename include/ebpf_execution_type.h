// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum _ebpf_execution_type
    {
        EBPF_EXECUTION_ANY,       ///< Execute in JIT-compiled or interpreted mode, per system policy.
        EBPF_EXECUTION_JIT,       ///< Execute in JIT-compiled mode.
        EBPF_EXECUTION_INTERPRET, ///< Execute in interpreted mode.
        EBPF_EXECUTION_NATIVE     ///< Execute from native driver.
    } ebpf_execution_type_t;

#ifdef __cplusplus
}
#endif
