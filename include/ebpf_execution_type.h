// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum _ebpf_execution_type
    {
        EBPF_EXECUTION_JIT,
        EBPF_EXECUTION_INTERPRET
    } ebpf_execution_type_t;

#ifdef __cplusplus
}
#endif
