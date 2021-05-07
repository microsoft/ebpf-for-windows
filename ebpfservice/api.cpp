/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "pch.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif
#include "rpc_interface_h.h"
#ifdef __cplusplus
}
#endif


#ifdef __cplusplus
    extern "C"
    {
#endif
ebpf_result_t ebpf_verify_and_jit_program(
    /* [in] */ ebpf_program_load_info* info,
    /* [out] */ uint32_t* log_size,
    /* [size_is][size_is][out] */ unsigned char** logs)
{
    UNREFERENCED_PARAMETER(info);
    UNREFERENCED_PARAMETER(log_size);
    UNREFERENCED_PARAMETER(logs);

    return EBPF_SUCCESS;
}

ebpf_result_t ebpf_verify_program(
    /* [in] */ ebpf_program_verify_info* info,
    /* [out] */ uint32_t* log_size,
    /* [size_is][size_is][out] */ unsigned char** logs)
{
    UNREFERENCED_PARAMETER(info);
    UNREFERENCED_PARAMETER(log_size);
    UNREFERENCED_PARAMETER(logs);

    return EBPF_SUCCESS;
}

#ifdef __cplusplus
    }
#endif
