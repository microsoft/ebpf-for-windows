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
        struct
        {
            ebpf_memory_descriptor_t* code_memory_descriptor;
            uint8_t* code_pointer;
        } code;

        // EBPF_CODE_EBPF
        struct ubpf_vm* vm;
    } code_or_vm;

    ebpf_extension_client_t* global_helper_extension_client;
    ebpf_extension_data_t* global_helper_provider_data;
    ebpf_extension_dispatch_table_t* global_helper_provider_dispatch_table;

    ebpf_map_t** maps;
    size_t count_of_maps;

    ebpf_extension_client_t* program_information_client;
    const void* program_information_binding_context;
    const ebpf_extension_data_t* program_information_data;
    const ebpf_extension_dispatch_table_t* program_information_provider_dispatch_table;
    bool program_invalidated;

    size_t trampoline_entry_count;
    ebpf_trampoline_entry_t* trampoline_entries;

    ebpf_epoch_work_item_t* cleanup_work_item;
} ebpf_program_t;

static void
_ebpf_program_program_information_provider_changed(
    void* client_binding_context,
    const void* provider_binding_context,
    const ebpf_extension_data_t* provider_data,
    const ebpf_extension_dispatch_table_t* provider_dispatch_table)
{
    ebpf_result_t return_value;
    ebpf_program_t* program = (ebpf_program_t*)client_binding_context;

    if (program->program_information_provider_dispatch_table != NULL) {
        if (provider_dispatch_table == NULL) {
            program->program_invalidated = true;
            return;
        }

        return_value = ebpf_build_trampoline_table(
            &program->trampoline_entry_count, &program->trampoline_entries, provider_dispatch_table);
        if (return_value != EBPF_SUCCESS) {
            program->program_invalidated = true;
            return;
        }
    }

    program->program_information_provider_dispatch_table = provider_dispatch_table;
    program->program_information_binding_context = provider_binding_context;
    program->program_information_data = provider_data;
}

/**
 * @brief Free invoked by ebpf_object_t reference tracking. This schedules the
 * final delete of the ebpf_program_t once the current epoch ends.
 *
 * @param[in] object Pointer to ebpf_object_t whose ref-count reached zero.
 */
static void
_ebpf_program_free(ebpf_object_t* object)
{
    ebpf_program_t* program = (ebpf_program_t*)object;
    if (!program)
        return;

    ebpf_epoch_schedule_work_item(program->cleanup_work_item);
}

/**
 * @brief Free invoked when the current epoch ends. Scheduled by
 * _ebpf_program_free.
 *
 * @param[in] context Pointer to the ebpf_program_t passed as context in the
 * work-item.
 */
static void
_ebpf_program_epoch_free(void* context)
{
    ebpf_program_t* program = (ebpf_program_t*)context;
    size_t index;

    ebpf_extension_unload(program->global_helper_extension_client);
    ebpf_extension_unload(program->program_information_client);

    switch (program->parameters.code_type) {
    case EBPF_CODE_NATIVE:
        ebpf_unmap_memory(program->code_or_vm.code.code_memory_descriptor);
        break;
    case EBPF_CODE_EBPF:
        ubpf_destroy(program->code_or_vm.vm);
        break;
    case EBPF_CODE_NONE:
        break;
    }

    ebpf_free(program->parameters.program_name.value);
    ebpf_free(program->parameters.section_name.value);

    for (index = 0; index < program->count_of_maps; index++)
        ebpf_object_release_reference((ebpf_object_t*)program->maps[index]);

    ebpf_free(program->maps);

    ebpf_free(program->cleanup_work_item);
    ebpf_free(program);
}

static ebpf_result_t
ebpf_program_load_providers(ebpf_program_t* program)
{
    ebpf_result_t return_value;
    void* provider_binding_context;
    program->program_invalidated = false;

    return_value = ebpf_extension_load(
        &program->global_helper_extension_client,
        &ebpf_global_helper_function_interface_id,
        program,
        NULL,
        NULL,
        &provider_binding_context,
        &program->global_helper_provider_data,
        &program->global_helper_provider_dispatch_table,
        NULL);

    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = ebpf_extension_load(
        &program->program_information_client,
        &program->parameters.program_type,
        program,
        NULL,
        NULL,
        (void**)&program->program_information_binding_context,
        &program->program_information_data,
        &program->program_information_provider_dispatch_table,
        _ebpf_program_program_information_provider_changed);

    if (return_value != EBPF_SUCCESS)
        goto Done;
Done:
    return return_value;
}

ebpf_result_t
ebpf_program_create(ebpf_program_t** program)
{
    ebpf_result_t retval;
    ebpf_program_t* local_program;

    local_program = (ebpf_program_t*)ebpf_allocate(sizeof(ebpf_program_t), EBPF_MEMORY_NO_EXECUTE);
    if (!local_program) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(local_program, 0, sizeof(ebpf_program_t));

    local_program->cleanup_work_item = ebpf_epoch_allocate_work_item(local_program, _ebpf_program_epoch_free);
    if (!local_program->cleanup_work_item) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    ebpf_object_initialize(&local_program->object, EBPF_OBJECT_PROGRAM, _ebpf_program_free);

    *program = local_program;
    local_program = NULL;
    retval = EBPF_SUCCESS;

Done:
    if (local_program)
        _ebpf_program_epoch_free(local_program);

    return retval;
}

ebpf_result_t
ebpf_program_initialize(ebpf_program_t* program, const ebpf_program_parameters_t* program_parameters)
{
    ebpf_result_t return_value;
    ebpf_utf8_string_t local_program_name = {NULL, 0};
    ebpf_utf8_string_t local_section_name = {NULL, 0};

    if (program->parameters.code_type != EBPF_CODE_NONE) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    return_value = ebpf_duplicate_utf8_string(&local_program_name, &program_parameters->program_name);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = ebpf_duplicate_utf8_string(&local_section_name, &program_parameters->section_name);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    program->parameters = *program_parameters;

    program->parameters.program_name = local_program_name;
    local_program_name.value = NULL;
    program->parameters.section_name = local_section_name;
    local_section_name.value = NULL;

    program->parameters.code_type = EBPF_CODE_NONE;

    return_value = ebpf_program_load_providers(program);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(local_program_name.value);
    ebpf_free(local_section_name.value);
    return return_value;
}

ebpf_result_t
ebpf_program_get_properties(ebpf_program_t* program, ebpf_program_parameters_t* program_parameters)
{
    *program_parameters = program->parameters;
    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_program_associate_maps(ebpf_program_t* program, ebpf_map_t** maps, size_t maps_count)
{
    size_t index;
    program->maps = ebpf_allocate(maps_count * sizeof(ebpf_map_t*), EBPF_MEMORY_NO_EXECUTE);
    if (!program->maps)
        return EBPF_NO_MEMORY;

    memcpy(program->maps, maps, sizeof(ebpf_map_t*) * maps_count);
    program->count_of_maps = maps_count;
    for (index = 0; index < program->count_of_maps; index++)
        ebpf_object_acquire_reference((ebpf_object_t*)program->maps[index]);

    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_program_load_machine_code(ebpf_program_t* program, uint8_t* machine_code, size_t machine_code_size)
{
    ebpf_result_t return_value;
    uint8_t* local_machine_code = NULL;
    ebpf_memory_descriptor_t* local_code_memory_descriptor = NULL;

    if (program->parameters.code_type != EBPF_CODE_NONE) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    local_code_memory_descriptor = ebpf_map_memory(machine_code_size);
    if (!local_code_memory_descriptor) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }
    local_machine_code = ebpf_memory_descriptor_get_base_address(local_code_memory_descriptor);

    memcpy(local_machine_code, machine_code, machine_code_size);

    return_value = ebpf_protect_memory(local_code_memory_descriptor, EBPF_PAGE_PROTECT_READ_EXECUTE);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    program->parameters.code_type = EBPF_CODE_NATIVE;
    program->code_or_vm.code.code_memory_descriptor = local_code_memory_descriptor;
    program->code_or_vm.code.code_pointer = local_machine_code;
    local_code_memory_descriptor = NULL;

    return_value = EBPF_SUCCESS;

Done:
    ebpf_unmap_memory(local_code_memory_descriptor);

    return return_value;
}

static ebpf_result_t
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
            return EBPF_INVALID_ARGUMENT;
    }
    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_program_load_byte_code(ebpf_program_t* program, ebpf_instuction_t* instructions, size_t instruction_count)
{
    ebpf_result_t return_value;
    char* error_message = NULL;
    if (program->parameters.code_type != EBPF_CODE_NONE) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    program->parameters.code_type = EBPF_CODE_EBPF;
    program->code_or_vm.vm = ubpf_create();
    if (!program->code_or_vm.vm) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    // https://github.com/iovisor/ubpf/issues/68
    // BUG - ubpf implements bounds checking to detect interpreted code accessing
    // memory out of bounds. Currently this is flagging valid access checks and
    // failing.
    ubpf_toggle_bounds_check(program->code_or_vm.vm, false);

    return_value = _ebpf_program_register_helpers(program);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    if (ubpf_load(
            program->code_or_vm.vm,
            instructions,
            (uint32_t)(instruction_count * sizeof(ebpf_instuction_t)),
            &error_message) != 0) {
        ebpf_free(error_message);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

Done:
    if (return_value != EBPF_SUCCESS) {
        ubpf_destroy(program->code_or_vm.vm);
        program->code_or_vm.vm = NULL;
    }

    return return_value;
}

void
ebpf_program_invoke(ebpf_program_t* program, void* context, uint32_t* result)
{
    if (program->program_invalidated)
        return;

    if (program->parameters.code_type == EBPF_CODE_NATIVE) {
        ebpf_program_entry_point_t function_pointer;
        function_pointer = (ebpf_program_entry_point_t)(program->code_or_vm.code.code_pointer);
        *result = (function_pointer)(context);
    } else {
        *result = (uint32_t)(ubpf_exec(program->code_or_vm.vm, context, 1024));
    }
}

ebpf_result_t
ebpf_program_get_helper_function_address(const ebpf_program_t* program, uint32_t helper_function_id, uint64_t* address)
{
    size_t count = (program->global_helper_provider_dispatch_table->size -
                    EBPF_OFFSET_OF(ebpf_extension_dispatch_table_t, function)) /
                   sizeof(program->global_helper_provider_dispatch_table->function);
    if (helper_function_id > EBPF_MAX_GLOBAL_HELPER_FUNCTION) {
        helper_function_id >>= 16;
        if ((program->trampoline_entries == NULL) || (helper_function_id > program->trampoline_entry_count))
            return EBPF_INVALID_ARGUMENT;

        *address = (uint64_t)(program->trampoline_entries + helper_function_id);
    } else {
        if (helper_function_id > count) {
            return EBPF_INVALID_ARGUMENT;
        }
        *address = (uint64_t)program->global_helper_provider_dispatch_table->function[helper_function_id];
    }

    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_program_get_program_information_data(
    const ebpf_program_t* program, const ebpf_extension_data_t** program_information_data)
{
    if (program->program_invalidated)
        return EBPF_ERROR_EXTENSION_FAILED_TO_LOAD;

    if (!program->program_information_data)
        return EBPF_ERROR_EXTENSION_FAILED_TO_LOAD;

    *program_information_data = program->program_information_data;

    return EBPF_SUCCESS;
}
