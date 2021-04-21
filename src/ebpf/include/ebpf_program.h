/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include "ebpf_hook.h"
#include "ebpf_maps.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct _ebpf_program ebpf_program_t;
    typedef struct _ebpf_program_parameters ebpf_program_parameters_t;
    typedef struct _ebpf_program_properties ebpf_program_properties_t;

    typedef ebpf_error_code_t (*ebpf_program_entry_point)(void* context);

    ebpf_error_code_t
    ebpf_program_create(ebpf_program_t** program);

    ebpf_error_code_t
    ebpf_program_initialize(ebpf_program_t* program, ebpf_program_parameters_t* program_parameters);

    ebpf_error_code_t
    ebpf_program_get_properties(ebpf_program_t* program, ebpf_program_properties_t** program_properties);

    ebpf_error_code_t
    ebpf_program_associate_maps(ebpf_program_t* program, ebpf_map_t** maps, size_t maps_count);

    ebpf_error_code_t
    ebpf_program_load_machine_code(ebpf_program_t* program, uint8_t* machine_code, size_t machine_code_size);

    ebpf_error_code_t
    ebpf_program_load_byte_code(ebpf_program_t* program, uint64_t* instructions, size_t instruction_count);

    ebpf_error_code_t
    ebpf_program_create_and_attach_hook(
        ebpf_program_t* program,
        ebpf_attach_type_t attach_type,
        uint8_t* context_data,
        size_t context_data_length,
        ebpf_hook_instance_t** hook_instance);

    ebpf_error_code_t
    ebpf_program_attach_hook(ebpf_program_t* program, ebpf_hook_instance_t* hook_instance);

    void
    ebpf_program_acquire_reference(ebpf_program_t* program);

    void
    ebpf_program_release_reference(ebpf_program_t* program);

    ebpf_error_code_t
    ebpf_program_get_entry_point(ebpf_program_t* program, ebpf_program_entry_point* program_entry_point);

#ifdef __cplusplus
}
#endif
