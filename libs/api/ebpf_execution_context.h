/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum ebpf_execution_context
    {
        execution_context_user_mode,
        execution_context_kernel_mode
    } ebpf_execution_context_t;

#ifdef __cplusplus
}
#endif
