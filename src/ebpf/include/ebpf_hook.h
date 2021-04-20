/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include "ebpf_platform.h"
#include "ebpf_program.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef GUID ebpf_hook_type_t;
    typedef struct _ebpf_hook ebpf_hook_t;

    ebpf_error_code_t
    ebpf_hook_create(ebpf_hook_t** hook);

    ebpf_error_code_t
    ebpf_hook_initialize(
        ebpf_hook_t* hook, ebpf_hook_type_t hook_type, uint8_t* context_data, size_t context_data_length);

    ebpf_error_code_t
    ebpf_hook_get_properties(ebpf_hook_t* hook, uint8_t** hook_properties, size_t* hook_properties_length);

    ebpf_error_code_t
    ebpf_hook_attach_program(ebpf_hook_t* hook, ebpf_program_t* program);

    void
    ebpf_hook_detach_program(ebpf_hook_t* hook);

    void
    ebpf_hook_acquire_reference(ebpf_hook_t* hook);

    void
    ebpf_hook_release_reference(ebpf_hook_t* hook);

    ebpf_error_code_t
    ebpf_hook_invoke(ebpf_hook_t* hook, void* program_context);

#ifdef __cplusplus
}
#endif
