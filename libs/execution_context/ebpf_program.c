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

    ebpf_extension_client_t* general_helper_extension_client;
    ebpf_extension_data_t* general_helper_provider_data;
    ebpf_extension_dispatch_table_t* general_helper_provider_dispatch_table;

    ebpf_map_t** maps;
    size_t count_of_maps;

    ebpf_extension_client_t* program_info_client;
    const void* program_info_binding_context;
    const ebpf_extension_data_t* program_info_provider_data;
    uint32_t helper_function_count;
    bool program_invalidated;

    ebpf_trampoline_table_t* trampoline_table;

    ebpf_epoch_work_item_t* cleanup_work_item;

    ebpf_list_entry_t links;
    ebpf_lock_t links_lock;
} ebpf_program_t;

static void
_ebpf_program_detach_links(_Inout_ ebpf_program_t* program)
{
    while (!ebpf_list_is_empty(&program->links)) {
        ebpf_list_entry_t* entry = program->links.Flink;
        ebpf_link_entry_detach_program(entry);
    }
}

static void
_ebpf_program_program_info_provider_changed(
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
            // A program info provider cannot modify helper function count upon reload.
            goto Exit;

        if (helper_function_addresses != NULL) {
            if (!program->trampoline_table) {
                // Program info provider is being loaded for the first time. Allocate trampoline table.
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

    program->program_info_binding_context = provider_binding_context;
    program->program_info_provider_data = provider_data;
Exit:
    program->program_invalidated = (program->program_info_provider_data == NULL);
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
    if (!program) {
        return;
    }

    // Detach from all the attach points.
    _ebpf_program_detach_links(program);
    ebpf_assert(ebpf_list_is_empty(&program->links));

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

    ebpf_lock_destroy(&program->links_lock);

    ebpf_extension_unload(program->general_helper_extension_client);
    ebpf_extension_unload(program->program_info_client);

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
    ebpf_program_data_t* general_helper_program_data = NULL;

    program->program_invalidated = false;

    return_value = ebpf_extension_load(
        &program->general_helper_extension_client,
        &ebpf_general_helper_function_interface_id,
        program,
        NULL,
        NULL,
        &provider_binding_context,
        &program->general_helper_provider_data,
        &program->general_helper_provider_dispatch_table,
        NULL);

    if (return_value != EBPF_SUCCESS)
        goto Done;

    if (program->general_helper_provider_data == NULL) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    general_helper_program_data = (ebpf_program_data_t*)program->general_helper_provider_data->data;
    if (general_helper_program_data->helper_function_addresses == NULL) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    return_value = ebpf_extension_load(
        &program->program_info_client,
        &program->parameters.program_type,
        program,
        NULL,
        NULL,
        (void**)&program->program_info_binding_context,
        &program->program_info_provider_data,
        NULL,
        _ebpf_program_program_info_provider_changed);

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

    ebpf_list_initialize(&program->links);
    ebpf_lock_create(&program->links_lock);

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
    ebpf_program_data_t* general_helper_program_data =
        (ebpf_program_data_t*)program->general_helper_provider_data->data;
    ebpf_helper_function_addresses_t* general_helper_function_addresses =
        general_helper_program_data->helper_function_addresses;
    size_t count = general_helper_function_addresses->helper_function_count;

    for (index = 0; index < count; index++) {
        const void* helper = (void*)general_helper_function_addresses->helper_function_address[index];
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
    if (helper_function_id > EBPF_MAX_GENERAL_HELPER_FUNCTION) {
        void* function_address;
        ebpf_result_t return_value;
        helper_function_id >>= 16;
        return_value = ebpf_get_trampoline_function(program->trampoline_table, helper_function_id, &function_address);
        if (return_value != EBPF_SUCCESS)
            return return_value;

        *address = (uint64_t)function_address;
    } else {
        ebpf_assert(program->general_helper_provider_data != NULL);
        ebpf_program_data_t* general_helper_program_data =
            (ebpf_program_data_t*)program->general_helper_provider_data->data;

        ebpf_helper_function_addresses_t* general_helper_function_addresses =
            general_helper_program_data->helper_function_addresses;

        ebpf_assert(general_helper_function_addresses != NULL);
        if (helper_function_id > general_helper_function_addresses->helper_function_count) {
            return EBPF_INVALID_ARGUMENT;
        }
        *address = general_helper_function_addresses->helper_function_address[helper_function_id];
    }

    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_program_get_program_info(_In_ const ebpf_program_t* program, _Outptr_ ebpf_program_info_t** program_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_data_t* program_data = NULL;
    ebpf_program_data_t* general_helper_program_data = NULL;
    ebpf_program_info_t* local_program_info = NULL;
    uint32_t total_count_of_helpers = 0;
    uint32_t helper_index = 0;

    if (program_info == NULL) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    *program_info = NULL;

    if (program->program_invalidated) {
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Exit;
    }

    if (!program->program_info_provider_data) {
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Exit;
    }
    program_data = (ebpf_program_data_t*)program->program_info_provider_data->data;

    if (!program->general_helper_provider_data) {
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Exit;
    }
    general_helper_program_data = (ebpf_program_data_t*)program->general_helper_provider_data->data;

    total_count_of_helpers =
        program_data->program_info->count_of_helpers + general_helper_program_data->program_info->count_of_helpers;
    if ((total_count_of_helpers < program_data->program_info->count_of_helpers) ||
        (total_count_of_helpers < general_helper_program_data->program_info->count_of_helpers)) {
        result = EBPF_ARITHMETIC_OVERFLOW;
        goto Exit;
    }

    // Allocate buffer and make a shallow copy of the program info.
    local_program_info = (ebpf_program_info_t*)ebpf_allocate(sizeof(ebpf_program_info_t));
    if (local_program_info == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    local_program_info->program_type_descriptor = program_data->program_info->program_type_descriptor;
    local_program_info->count_of_helpers = total_count_of_helpers;

    if (total_count_of_helpers > 0) {
        // Allocate buffer and make a shallow copy of the combined global and program-type specific helper function
        // prototypes.
        local_program_info->helper_prototype = (ebpf_helper_function_prototype_t*)ebpf_allocate(
            total_count_of_helpers * sizeof(ebpf_helper_function_prototype_t));
        if (local_program_info->helper_prototype == NULL) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        for (uint32_t index = 0; index < program_data->program_info->count_of_helpers; index++) {
            __analysis_assume(helper_index < total_count_of_helpers);
            local_program_info->helper_prototype[helper_index++] = program_data->program_info->helper_prototype[index];
        }

        for (uint32_t index = 0; index < general_helper_program_data->program_info->count_of_helpers; index++) {
            __analysis_assume(helper_index < total_count_of_helpers);
            local_program_info->helper_prototype[helper_index++] =
                general_helper_program_data->program_info->helper_prototype[index];
        }
    }

Exit:
    if (result == EBPF_SUCCESS) {
        *program_info = local_program_info;
        local_program_info = NULL;
    } else {
        ebpf_program_free_program_info(local_program_info);
    }

    return result;
}

void
ebpf_program_free_program_info(_In_opt_ _Post_invalid_ ebpf_program_info_t* program_info)
{
    if (program_info != NULL) {
        ebpf_free(program_info->helper_prototype);
        ebpf_free(program_info);
    }
}

void
ebpf_program_add_link_to_list(_Inout_ ebpf_program_t* program, _Inout_ ebpf_link_t* link)
{
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&program->links_lock);
    ebpf_link_insert_to_attach_list(&program->links, link);
    ebpf_lock_unlock(&program->links_lock, state);
}

void
ebpf_program_remove_link_from_list(_Inout_ ebpf_program_t* program, _Inout_ ebpf_link_t* link)
{
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&program->links_lock);
    ebpf_link_remove_from_attach_list(link);
    ebpf_lock_unlock(&program->links_lock, state);
}