// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_link.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_program_types.h"

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
    uint32_t helper_function_count;
    bool program_invalidated;

    ebpf_trampoline_table_t* trampoline_table;

    ebpf_epoch_work_item_t* cleanup_work_item;
} ebpf_program_t;

static void
_ebpf_program_program_information_provider_changed(
    _In_ void* client_binding_context,
    _In_ const void* provider_binding_context,
    _In_opt_ const ebpf_extension_data_t* provider_data)
{
    ebpf_result_t return_value;
    ebpf_program_t* program = (ebpf_program_t*)client_binding_context;

    if (provider_data == NULL) {
        // Extension is detaching. Program will get invalidated.
        goto Exit;
    } else {
        ebpf_helper_function_addresses_t* helper_function_addresses = NULL;

        ebpf_program_data_t* program_data = (ebpf_program_data_t*)provider_data->data;
        if (program_data == NULL) {
            // An extension cannot have empty program_data.
            goto Exit;
        }

        helper_function_addresses = program_data->helper_function_addresses;

        if ((program->helper_function_count > 0) &&
            (helper_function_addresses->helper_function_count != program->helper_function_count))
            // A program information provider cannot modify helper function count upon reload.
            goto Exit;

        if (helper_function_addresses != NULL) {
            if (!program->trampoline_table) {
                // Program information provider is being loaded for the first time. Allocate trampoline table.
                program->helper_function_count = helper_function_addresses->helper_function_count;
                return_value =
                    ebpf_allocate_trampoline_table(program->helper_function_count, &program->trampoline_table);
                if (return_value != EBPF_SUCCESS)
                    goto Exit;
            }

            // Update trampoline table with new helper function addresses.
            return_value = ebpf_update_trampoline_table(program->trampoline_table, helper_function_addresses);
            if (return_value != EBPF_SUCCESS)
                goto Exit;
        }
    }

    program->program_information_binding_context = provider_binding_context;
    program->program_information_data = provider_data;
Exit:
    program->program_invalidated = (program->program_information_data == NULL);
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

    ebpf_free_trampoline_table(program->trampoline_table);

    ebpf_free(program->cleanup_work_item);
    ebpf_free(program);
}

static ebpf_result_t
ebpf_program_load_providers(ebpf_program_t* program)
{
    ebpf_result_t return_value;
    void* provider_binding_context;
    ebpf_program_data_t* global_helper_program_data = NULL;

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

    if (program->global_helper_provider_data == NULL) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    global_helper_program_data = (ebpf_program_data_t*)program->global_helper_provider_data;
    if (global_helper_program_data->helper_function_addresses == NULL) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    return_value = ebpf_extension_load(
        &program->program_information_client,
        &program->parameters.program_type,
        program,
        NULL,
        NULL,
        (void**)&program->program_information_binding_context,
        &program->program_information_data,
        NULL,
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

    local_program = (ebpf_program_t*)ebpf_allocate(sizeof(ebpf_program_t));
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
    program->maps = ebpf_allocate(maps_count * sizeof(ebpf_map_t*));
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
    ebpf_program_data_t* global_helper_program_data = (ebpf_program_data_t*)program->global_helper_provider_data->data;
    ebpf_helper_function_addresses_t* global_helper_function_addresses =
        global_helper_program_data->helper_function_addresses;
    size_t count = global_helper_function_addresses->helper_function_count;

    for (index = 0; index < count; index++) {
        const void* helper = (void*)global_helper_function_addresses->helper_function_address[index];
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
ebpf_program_invoke(_In_ const ebpf_program_t* program, _In_ void* context, _Out_ uint32_t* result)
{
    if (!program || program->program_invalidated) {
        *result = 0;
        return;
    }

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
    if (helper_function_id > EBPF_MAX_GLOBAL_HELPER_FUNCTION) {
        void* function_address;
        ebpf_result_t return_value;
        helper_function_id >>= 16;
        return_value = ebpf_get_trampoline_function(program->trampoline_table, helper_function_id, &function_address);
        if (return_value != EBPF_SUCCESS)
            return return_value;

        *address = (uint64_t)function_address;
    } else {
        ebpf_assert(program->global_helper_provider_data != NULL);
        ebpf_program_data_t* global_helper_program_data =
            (ebpf_program_data_t*)program->global_helper_provider_data->data;

        ebpf_helper_function_addresses_t* global_helper_function_addresses =
            global_helper_program_data->helper_function_addresses;

        ebpf_assert(global_helper_function_addresses != NULL);
        if (helper_function_id > global_helper_function_addresses->helper_function_count) {
            return EBPF_INVALID_ARGUMENT;
        }
        *address = global_helper_function_addresses->helper_function_address[helper_function_id];
    }

    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_program_get_program_information_data(
    const ebpf_program_t* program, const ebpf_extension_data_t** program_information_data)
{
    if (program->program_invalidated)
        return EBPF_EXTENSION_FAILED_TO_LOAD;

    if (!program->program_information_data)
        return EBPF_EXTENSION_FAILED_TO_LOAD;

    *program_information_data = program->program_information_data;

    return EBPF_SUCCESS;
}
