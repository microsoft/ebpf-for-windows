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
    void
    ebpf_program_acquire_reference(ebpf_program_t* program);

    void
    ebpf_program_release_reference(ebpf_program_t* program);

    ebpf_error_code_t
    ebpf_program_get_entry_point(ebpf_program_t* program, ebpf_program_entry_point* program_entry_point);

#ifdef __cplusplus
}
#endif
