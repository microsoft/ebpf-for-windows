/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_program.h"

#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_link.h"
#include "ebpf_object.h"

typedef struct _FILE FILE;
#include "ubpf.h"

typedef struct _ebpf_program
{
    ebpf_object_t object;

    ebpf_program_parameters_t parameters;

    // determinant is parameters.code_type
    union
    {
        // EBPF_CODE_NATIVE
        uint8_t* code;

        // EBPF_CODE_EBPF
        struct ubpf_vm* vm;
    } code_or_vm;

    ebpf_extension_client_t* global_helper_extension_client;
    ebpf_extension_data_t* global_helper_provider_data;
    ebpf_extension_dispatch_table_t* global_helper_provider_dispatch_table;

    ebpf_map_t** maps;
    size_t count_of_maps;

} ebpf_program_t;

static void
_ebpf_program_free(ebpf_object_t* object)
{
    size_t index;
    ebpf_program_t* program = (ebpf_program_t*)object;
    if (!program)
        return;

    if (program->global_helper_extension_client) {
        ebpf_extension_unload(program->global_helper_extension_client);
    }

    if (program->parameters.code_type == EBPF_CODE_NATIVE) {
        ebpf_epoch_free(program->code_or_vm.code);
    } else {
        ubpf_destroy(program->code_or_vm.vm);
    }

    ebpf_free(program->parameters.program_name.value);
    ebpf_free(program->parameters.section_name.value);

    for (index = 0; index < program->count_of_maps; index++)
        ebpf_object_release_reference((ebpf_object_t*)program->maps[index]);

    ebpf_epoch_free(object);
}

ebpf_error_code_t
ebpf_program_create(ebpf_program_t** program)
{
    ebpf_program_t* local_program;

    local_program = (ebpf_program_t*)ebpf_epoch_allocate(sizeof(ebpf_program_t), EBPF_MEMORY_NO_EXECUTE);
    if (!local_program)
        return EBPF_ERROR_OUT_OF_RESOURCES;

    memset(local_program, 0, sizeof(ebpf_program_t));

    ebpf_object_initialize(&local_program->object, EBPF_OBJECT_PROGRAM, _ebpf_program_free);

    *program = local_program;

    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_program_initialize(ebpf_program_t* program, const ebpf_program_parameters_t* program_parameters)
{
    ebpf_error_code_t return_value;
    ebpf_utf8_string_t local_program_name = {NULL, 0};
    ebpf_utf8_string_t local_section_name = {NULL, 0};
    void* provider_binding_context;

    return_value = ebpf_extension_load(
        &program->global_helper_extension_client,
        &ebpf_global_helper_function_interface_id,
        program,
        NULL,
        NULL,
        &provider_binding_context,
        &program->global_helper_provider_data,
        &program->global_helper_provider_dispatch_table);

    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    return_value = ebpf_duplicate_utf8_string(&local_program_name, &program_parameters->program_name);
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    return_value = ebpf_duplicate_utf8_string(&local_section_name, &program_parameters->section_name);
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    program->parameters = *program_parameters;

    program->parameters.program_name = local_program_name;
    local_program_name.value = NULL;
    program->parameters.section_name = local_section_name;
    local_section_name.value = NULL;
    return_value = EBPF_ERROR_SUCCESS;

Done:
    ebpf_free(local_program_name.value);
    ebpf_free(local_section_name.value);
    return return_value;
}

ebpf_error_code_t
ebpf_program_get_properties(ebpf_program_t* program, ebpf_program_parameters_t* program_parameters)
{
    *program_parameters = program->parameters;
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_program_associate_maps(ebpf_program_t* program, ebpf_map_t** maps, size_t maps_count)
{
    size_t index;
    program->maps = ebpf_allocate(maps_count * sizeof(ebpf_map_t*), EBPF_MEMORY_NO_EXECUTE);
    if (!program->maps)
        return EBPF_ERROR_OUT_OF_RESOURCES;

    memcpy(program->maps, maps, sizeof(ebpf_map_t*) * maps_count);
    program->count_of_maps = maps_count;
    for (index = 0; index < program->count_of_maps; index++)
        ebpf_object_acquire_reference((ebpf_object_t*)program->maps[index]);

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

    program->parameters.code_type = EBPF_CODE_NATIVE;
    program->code_or_vm.code = local_machine_code;
    local_machine_code = NULL;

    return_value = EBPF_ERROR_SUCCESS;

Done:
    ebpf_epoch_free(local_machine_code);

    return return_value;
}

static ebpf_error_code_t
_ebpf_program_register_helpers(ebpf_program_t* program)
{
    size_t index = 0;
    size_t count = (program->global_helper_provider_dispatch_table->size -
                    EBPF_OFFSET_OF(ebpf_extension_dispatch_table_t, function)) /
                   sizeof(program->global_helper_provider_dispatch_table->function);

    for (index = 0; index < count; index++) {
        const void* helper = (void*)program->global_helper_provider_dispatch_table->function[index];
        if (helper == NULL)
            continue;

        if (ubpf_register(program->code_or_vm.vm, (unsigned int)index, NULL, (void*)helper) < 0)
            return EBPF_ERROR_INVALID_PARAMETER;
    }
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_program_load_byte_code(ebpf_program_t* program, ebpf_instuction_t* instructions, size_t instruction_count)
{
    ebpf_error_code_t return_value;
    char* error_message = NULL;
    program->parameters.code_type = EBPF_CODE_EBPF;
    program->code_or_vm.vm = ubpf_create();
    if (!program->code_or_vm.vm) {
        return_value = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }

    // BUG - ubpf implements bounds checking to detect interpreted code accessing
    // memory out of bounds. Currently this is flagging valid access checks and
    // failing.
    toggle_bounds_check(program->code_or_vm.vm, false);

    return_value = _ebpf_program_register_helpers(program);
    if (return_value != EBPF_ERROR_SUCCESS)
        goto Done;

    if (ubpf_load(
            program->code_or_vm.vm,
            instructions,
            (uint32_t)(instruction_count * sizeof(ebpf_instuction_t)),
            &error_message) != 0) {
        ebpf_free(error_message);
        return_value = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

Done:
    if (return_value != EBPF_ERROR_SUCCESS) {
        ubpf_destroy(program->code_or_vm.vm);
        program->code_or_vm.vm = NULL;
    }

    return return_value;
}

ebpf_error_code_t
ebpf_program_get_entry_point(ebpf_program_t* program, ebpf_program_entry_point_t* program_entry_point)
{
    if (program->parameters.code_type != EBPF_CODE_NATIVE) {
        return EBPF_ERROR_INVALID_PARAMETER;
    }
    *program_entry_point = (ebpf_program_entry_point_t)program->code_or_vm.code;
    return EBPF_ERROR_SUCCESS;
}

void
ebpf_program_invoke(ebpf_program_t* program, void* context, uint32_t* result)
{
    if (program->parameters.code_type == EBPF_CODE_NATIVE) {
        ebpf_program_entry_point_t function_pointer;
        function_pointer = (ebpf_program_entry_point_t)(program->code_or_vm.code);
        *result = (function_pointer)(context);
    } else {
        char* error_message = NULL;
        *result = (uint32_t)(ubpf_exec(program->code_or_vm.vm, context, 1024, &error_message));
        ebpf_free(error_message);
    }
}
