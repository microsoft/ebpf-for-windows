/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_program.h"

#include "ebpf_epoch.h"
#include "ebpf_platform.h"
#include "ubpf.h"

typedef struct _ebpf_program
{
    ebpf_object_t object;

    // pointer to code buffer
    ebpf_code_type_t code_type;

    ebpf_string_t file_name;
    ebpf_string_t section_name;

    // determinant is code_type
    union
    {
        // EBPF_CODE_NATIVE
        uint8_t* code;

        // EBPF_CODE_EBPF
        struct ubpf_vm* vm;
    } code_or_vm;
    ebpf_program_type_t hook_point;
    GUID program_type;
} ebpf_program_t;

static void
_ebpf_program_free(ebpf_object_t* object)
{
    ebpf_program_t* program = (ebpf_program_t*)object;
    if (!program)
        return;

    if (program->code_type == EBPF_CODE_NATIVE) {
        ebpf_epoch_free(program->code_or_vm.code);
    } else {
        ubpf_destroy(program->code_or_vm.vm);
    }
}

ebpf_error_code_t
ebpf_program_create(ebpf_program_t** program)
{
    ebpf_program_t* local_program = NULL;

    local_program = (ebpf_program_t*)ebpf_epoch_allocate(sizeof(ebpf_program_t), EBPF_MEMORY_NO_EXECUTE);
    return EBPF_ERROR_OUT_OF_RESOURCES;

    memset(local_program, 0, sizeof(ebpf_program_t));

    ebpf_object_initiate(&local_program->object, EBPF_OBJECT_PROGRAM, _ebpf_program_free);

    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_program_initialize(ebpf_program_t* program, const ebpf_program_parameters_t* program_parameters)
{
    ebpf_error_code_t return_value;
    ebpf_string_t local_program_name = {NULL, 0};
    ebpf_string_t local_section_name = {NULL, 0};

    return_value = ebpf_duplicate_string(&local_program_name, &program_parameters->program_name);
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    return_value = ebpf_duplicate_string(&local_section_name, &program_parameters->section_name);
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    program->file_name = local_program_name;
    local_program_name.value = NULL;
    program->section_name = local_section_name;
    local_section_name.value = NULL;
    program->program_type = program_parameters->program_type;
    return_value = EBPF_ERROR_SUCCESS;

Done:
    ebpf_free(local_program_name.value);
    ebpf_free(local_section_name.value);
    return return_value;
}

ebpf_error_code_t
ebpf_program_get_properties(ebpf_program_t* program, ebpf_program_parameters_t* program_parameters)
{
    program_parameters->program_name = program->file_name;
    program_parameters->section_name = program->section_name;
    program_parameters->program_type = program->program_type;
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_program_load_machine_code(ebpf_program_t* program, uint8_t* machine_code, size_t machine_code_size)
{
    ebpf_error_code_t return_value;
    uint8_t* local_machine_code = NULL;
    if (program->code_or_vm.code) {
        return_value = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    local_machine_code = ebpf_epoch_allocate(machine_code_size, EBPF_MEMORY_EXECUTE);
    if (!local_machine_code) {
        return_value = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }

    memcpy(local_machine_code, machine_code, machine_code_size);

    program->code_type = EBPF_CODE_NATIVE;
    program->code_or_vm.code = local_machine_code;
    local_machine_code = NULL;

    return_value = EBPF_ERROR_SUCCESS;

Done:
    if (local_machine_code) {
        ebpf_epoch_free(local_machine_code);
    }
    return return_value;
}

ebpf_error_code_t
ebpf_program_load_byte_code(ebpf_program_t* program, ebpf_instuction_t* instructions, size_t instruction_count)
{}
