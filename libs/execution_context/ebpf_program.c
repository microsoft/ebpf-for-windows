// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_native.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_program_types.h"
#include "ebpf_state.h"

#include "ubpf.h"

static size_t _ebpf_program_state_index = MAXUINT64;

typedef struct _ebpf_program
{
    ebpf_core_object_t object;

    ebpf_program_parameters_t parameters;

    // determinant is parameters.code_type
    union
    {
        // EBPF_CODE_JIT
        struct
        {
            ebpf_memory_descriptor_t* code_memory_descriptor;
            uint8_t* code_pointer;
        } code;

        // EBPF_CODE_EBPF
        struct ubpf_vm* vm;

        // EBPF_CODE_NATIVE
        struct
        {
            const ebpf_native_module_binding_context_t* module;
            const uint8_t* code_pointer;
        } native;
    } code_or_vm;

    ebpf_extension_client_t* general_helper_extension_client;
    ebpf_extension_data_t* general_helper_provider_data;
    ebpf_extension_dispatch_table_t* general_helper_provider_dispatch_table;

    ebpf_extension_client_t* info_extension_client;
    const void* info_extension_provider_binding_context;
    const ebpf_extension_data_t* info_extension_provider_data;
    // Program type specific helper function count.
    uint32_t provider_helper_function_count;
    // Global helper function count implemented by the extension.
    uint32_t global_helper_function_count;
    bool invalidated;

    ebpf_trampoline_table_t* trampoline_table;
    ebpf_trampoline_table_t* global_helper_trampoline_table;

    // Array of helper function ids referred by this program.
    size_t helper_function_count;
    uint32_t* helper_function_ids;

    ebpf_epoch_work_item_t* cleanup_work_item;

    // Lock protecting the fields below.
    ebpf_lock_t lock;

    ebpf_list_entry_t links;
    uint32_t link_count;
    ebpf_map_t** maps;
    uint32_t count_of_maps;
} ebpf_program_t;

static ebpf_result_t
_ebpf_program_register_helpers(_In_ const ebpf_program_t* program);

static ebpf_result_t
_ebpf_program_get_helper_function_address(
    _In_ const ebpf_program_t* program, const uint32_t helper_function_id, uint64_t* address);

_Must_inspect_result_ ebpf_result_t
ebpf_program_initiate()
{
    return ebpf_state_allocate_index(&_ebpf_program_state_index);
}

void
ebpf_program_terminate()
{}

static void
_ebpf_program_detach_links(_Inout_ ebpf_program_t* program)
{
    EBPF_LOG_ENTRY();
    while (!ebpf_list_is_empty(&program->links)) {
        ebpf_list_entry_t* entry = program->links.Flink;
        ebpf_core_object_t* object = CONTAINING_RECORD(entry, ebpf_core_object_t, object_list_entry);
        ebpf_link_detach_program((ebpf_link_t*)object);
    }
    EBPF_RETURN_VOID();
}

static void
_ebpf_program_program_info_provider_changed(
    _In_ const void* client_binding_context,
    _In_ const void* provider_binding_context,
    _In_opt_ const ebpf_extension_data_t* provider_data)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_program_t* program = (ebpf_program_t*)client_binding_context;
    uint32_t* provider_helper_function_ids = NULL;
    uint32_t* global_helper_function_ids = NULL;

    if (provider_data == NULL) {
        // Extension is detaching. Program will get invalidated.
        goto Exit;
    } else {
        ebpf_helper_function_addresses_t* helper_function_addresses = NULL;
        ebpf_helper_function_addresses_t* global_helper_function_addresses = NULL;

        ebpf_program_data_t* program_data = (ebpf_program_data_t*)provider_data->data;
        if (program_data == NULL) {
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_PROGRAM,
                "An extension cannot have empty program_data",
                program->parameters.program_type);
            // An extension cannot have empty program_data.
            goto Exit;
        }

        helper_function_addresses = program_data->helper_function_addresses;
        global_helper_function_addresses = program_data->global_helper_function_addresses;

        if ((program->provider_helper_function_count > 0) &&
            (helper_function_addresses->helper_function_count != program->provider_helper_function_count)) {

            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_PROGRAM,
                "A program info provider cannot modify helper function count upon reload",
                program->parameters.program_type);
            // A program info provider cannot modify helper function count upon reload.
            goto Exit;
        }
        if ((program->global_helper_function_count > 0) &&
            (helper_function_addresses->helper_function_count != program->provider_helper_function_count)) {

            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_PROGRAM,
                "A program info provider cannot modify global helper function count upon reload",
                program->parameters.program_type);
            // A program info provider cannot modify helper function count upon reload.
            goto Exit;
        }

        if (helper_function_addresses != NULL || global_helper_function_addresses != NULL) {
            ebpf_program_info_t* program_info = program_data->program_info;
            ebpf_helper_function_prototype_t* helper_prototypes = NULL;
            ebpf_assert(program_info != NULL);
            _Analysis_assume_(program_info != NULL);
            if ((helper_function_addresses != NULL &&
                 program_info->count_of_helpers != helper_function_addresses->helper_function_count) ||
                (global_helper_function_addresses != NULL &&
                 program_info->count_of_global_helpers != global_helper_function_addresses->helper_function_count)) {
                EBPF_LOG_MESSAGE_GUID(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_PROGRAM,
                    "A program info provider cannot modify helper function count upon reload",
                    program->parameters.program_type);
                return_value = EBPF_INVALID_ARGUMENT;
                goto Exit;
            }

            if (helper_function_addresses != NULL) {
                helper_prototypes = program_info->helper_prototype;
                if (helper_prototypes == NULL) {
                    EBPF_LOG_MESSAGE_GUID(
                        EBPF_TRACELOG_LEVEL_ERROR,
                        EBPF_TRACELOG_KEYWORD_PROGRAM,
                        "program_info->helper_prototype can not be NULL",
                        program->parameters.program_type);
                    return_value = EBPF_INVALID_ARGUMENT;
                    goto Exit;
                }
                if (!program->trampoline_table) {
                    // Program info provider is being loaded for the first time. Allocate trampoline table.
                    program->provider_helper_function_count = helper_function_addresses->helper_function_count;
                    return_value = ebpf_allocate_trampoline_table(
                        program->provider_helper_function_count, &program->trampoline_table);
                    if (return_value != EBPF_SUCCESS)
                        goto Exit;
                }
                _Analysis_assume_(program->provider_helper_function_count > 0);
                provider_helper_function_ids =
                    (uint32_t*)ebpf_allocate(sizeof(uint32_t) * program->provider_helper_function_count);
                if (provider_helper_function_ids == NULL) {
                    return_value = EBPF_NO_MEMORY;
                    goto Exit;
                }
                for (uint32_t index = 0; index < program->provider_helper_function_count; index++)
                    provider_helper_function_ids[index] = helper_prototypes[index].helper_id;

                // Update trampoline table with new helper function addresses.
                return_value = ebpf_update_trampoline_table(
                    program->trampoline_table,
                    program->provider_helper_function_count,
                    provider_helper_function_ids,
                    helper_function_addresses);
                if (return_value != EBPF_SUCCESS)
                    goto Exit;
            }

            if (global_helper_function_addresses != NULL) {
                helper_prototypes = program_info->global_helper_prototype;
                if (helper_prototypes == NULL) {
                    EBPF_LOG_MESSAGE_GUID(
                        EBPF_TRACELOG_LEVEL_ERROR,
                        EBPF_TRACELOG_KEYWORD_PROGRAM,
                        "program_info->global_helper_prototype can not be NULL",
                        program->parameters.program_type);
                    return_value = EBPF_INVALID_ARGUMENT;
                    goto Exit;
                }
                if (!program->global_helper_trampoline_table) {
                    // Program info provider is being loaded for the first time. Allocate trampoline table.
                    program->global_helper_function_count = global_helper_function_addresses->helper_function_count;
                    return_value = ebpf_allocate_trampoline_table(
                        program->global_helper_function_count, &program->global_helper_trampoline_table);
                    if (return_value != EBPF_SUCCESS)
                        goto Exit;
                }
                _Analysis_assume_(program->global_helper_function_count > 0);
                global_helper_function_ids =
                    (uint32_t*)ebpf_allocate(sizeof(uint32_t) * program->global_helper_function_count);
                if (global_helper_function_ids == NULL) {
                    return_value = EBPF_NO_MEMORY;
                    goto Exit;
                }
                for (uint32_t index = 0; index < program->global_helper_function_count; index++)
                    global_helper_function_ids[index] = helper_prototypes[index].helper_id;
                // Update trampoline table with new helper function addresses.
                return_value = ebpf_update_trampoline_table(
                    program->global_helper_trampoline_table,
                    program->global_helper_function_count,
                    global_helper_function_ids,
                    global_helper_function_addresses);
                if (return_value != EBPF_SUCCESS)
                    goto Exit;
            }

#if !defined(CONFIG_BPF_JIT_ALWAYS_ON)
            if (program->code_or_vm.vm != NULL) {
                // Register with uBPF for interpreted mode.
                return_value = _ebpf_program_register_helpers(program);
                if (return_value != EBPF_SUCCESS)
                    goto Exit;
            }
#endif
        }
    }

    program->info_extension_provider_binding_context = provider_binding_context;
    program->info_extension_provider_data = provider_data;
Exit:
    ebpf_free(provider_helper_function_ids);
    ebpf_free(global_helper_function_ids);
    program->invalidated = (program->info_extension_provider_data == NULL);
    EBPF_RETURN_VOID();
}

/**
 * @brief Free invoked by ebpf_core_object_t reference tracking. This schedules the
 * final delete of the ebpf_program_t once the current epoch ends.
 *
 * @param[in] object Pointer to ebpf_core_object_t whose ref-count reached zero.
 */
static void
_ebpf_program_free(_In_opt_ _Post_invalid_ ebpf_core_object_t* object)
{
    EBPF_LOG_ENTRY();
    size_t index;
    ebpf_program_t* program = (ebpf_program_t*)object;
    if (!program)
        EBPF_RETURN_VOID();

    // Detach from all the attach points.
    _ebpf_program_detach_links(program);
    ebpf_assert(ebpf_list_is_empty(&program->links));

    for (index = 0; index < program->count_of_maps; index++)
        ebpf_object_release_reference((ebpf_core_object_t*)program->maps[index]);

    ebpf_epoch_schedule_work_item(program->cleanup_work_item);
    EBPF_RETURN_VOID();
}

static const ebpf_program_type_t*
_ebpf_program_get_program_type(_In_ const ebpf_core_object_t* object)
{
    return ebpf_program_type_uuid((const ebpf_program_t*)object);
}

static const bpf_prog_type_t
_ebpf_program_get_bpf_prog_type(_In_ const ebpf_program_t* program)
{
    bpf_prog_type_t prog_type = BPF_PROG_TYPE_UNSPEC;
    if (program->info_extension_provider_binding_context != NULL) {
        ebpf_program_data_t* program_data = (ebpf_program_data_t*)program->info_extension_provider_data->data;
        prog_type = program_data->program_info->program_type_descriptor.bpf_prog_type;
    }

    return prog_type;
}

/**
 * @brief Free invoked when the current epoch ends. Scheduled by
 * _ebpf_program_free.
 *
 * @param[in] context Pointer to the ebpf_program_t passed as context in the
 * work-item.
 */
static void
_ebpf_program_epoch_free(_In_ _Post_invalid_ void* context)
{
    EBPF_LOG_ENTRY();
    ebpf_program_t* program = (ebpf_program_t*)context;

    ebpf_lock_destroy(&program->lock);

    ebpf_extension_unload(program->general_helper_extension_client);
    ebpf_extension_unload(program->info_extension_client);

    switch (program->parameters.code_type) {
    case EBPF_CODE_JIT:
        ebpf_unmap_memory(program->code_or_vm.code.code_memory_descriptor);
        break;
#if !defined(CONFIG_BPF_JIT_ALWAYS_ON)
    case EBPF_CODE_EBPF:
        if (program->code_or_vm.vm) {
            ubpf_destroy(program->code_or_vm.vm);
        }
        break;
#endif
    case EBPF_CODE_NATIVE:
        ebpf_native_release_reference((ebpf_native_module_binding_context_t*)program->code_or_vm.native.module);
        break;
    case EBPF_CODE_NONE:
        break;
    }

    ebpf_free(program->parameters.program_name.value);
    ebpf_free(program->parameters.section_name.value);
    ebpf_free(program->parameters.file_name.value);

    ebpf_free(program->maps);

    ebpf_free_trampoline_table(program->trampoline_table);
    ebpf_free_trampoline_table(program->global_helper_trampoline_table);

    ebpf_free(program->helper_function_ids);

    ebpf_free(program->cleanup_work_item);
    ebpf_free(program);
    EBPF_RETURN_VOID();
}

static ebpf_result_t
ebpf_program_load_providers(_Inout_ ebpf_program_t* program)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    void* provider_binding_context;
    ebpf_program_data_t* general_helper_program_data = NULL;
    GUID module_id = {0};

    // First, register as a client of the general helper function
    // provider and get the general helper program data.

    return_value = ebpf_guid_create(&module_id);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    program->invalidated = false;

    return_value = ebpf_extension_load(
        &program->general_helper_extension_client,
        &ebpf_program_information_extension_interface_id, // Load program information extension.
        &ebpf_general_helper_function_module_id,          // Expected provider module Id.
        &module_id,
        program,
        NULL,
        NULL,
        &provider_binding_context,
        &program->general_helper_provider_data,
        &program->general_helper_provider_dispatch_table,
        NULL);

    if (return_value != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Failed to load general helper functions",
            ebpf_general_helper_function_module_id);
        goto Done;
    }

    if (program->general_helper_provider_data == NULL) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "program->general_helper_provider_data can not be NULL",
            ebpf_general_helper_function_module_id);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    general_helper_program_data = (ebpf_program_data_t*)program->general_helper_provider_data->data;
    if (general_helper_program_data->helper_function_addresses == NULL) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "general_helper_program_data->helper_function_addresses can not be NULL",
            ebpf_general_helper_function_module_id);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Next, register as a client of the specific program type
    // provider and get the data associated with that program type.

    return_value = ebpf_guid_create(&module_id);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_extension_load(
        &program->info_extension_client,
        &ebpf_program_information_extension_interface_id, // Load program information extension.
        &program->parameters.program_type,                // Program type is the expected provider module Id.
        &module_id,
        program,
        NULL,
        NULL,
        (void**)&program->info_extension_provider_binding_context,
        &program->info_extension_provider_data,
        NULL,
        _ebpf_program_program_info_provider_changed);

    if (return_value != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Failed to load program information provider",
            program->parameters.program_type);

        goto Done;
    }
Done:
    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_create(_Outptr_ ebpf_program_t** program)
{
    EBPF_LOG_ENTRY();
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

    ebpf_list_initialize(&local_program->links);
    ebpf_lock_create(&local_program->lock);

    retval = ebpf_object_initialize(
        &local_program->object, EBPF_OBJECT_PROGRAM, _ebpf_program_free, _ebpf_program_get_program_type);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    *program = local_program;
    local_program = NULL;
    retval = EBPF_SUCCESS;

Done:
    if (local_program)
        _ebpf_program_epoch_free(local_program);

    EBPF_RETURN_RESULT(retval);
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_initialize(_Inout_ ebpf_program_t* program, _In_ const ebpf_program_parameters_t* program_parameters)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_utf8_string_t local_program_name = {NULL, 0};
    ebpf_utf8_string_t local_section_name = {NULL, 0};
    ebpf_utf8_string_t local_file_name = {NULL, 0};

    if (program->parameters.code_type != EBPF_CODE_NONE) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "ebpf_program_initialize program->parameters.code_type must be EBPF_CODE_NONE",
            program->parameters.code_type);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }
    if (program_parameters->program_name.length >= BPF_OBJ_NAME_LEN) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Program name must be less than BPF_OBJ_NAME_LEN",
            program_parameters->program_name.length);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    return_value = ebpf_duplicate_utf8_string(&local_program_name, &program_parameters->program_name);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = ebpf_duplicate_utf8_string(&local_section_name, &program_parameters->section_name);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = ebpf_duplicate_utf8_string(&local_file_name, &program_parameters->file_name);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    program->parameters = *program_parameters;

    program->parameters.program_name = local_program_name;
    local_program_name.value = NULL;
    program->parameters.section_name = local_section_name;
    local_section_name.value = NULL;
    program->parameters.file_name = local_file_name;
    local_file_name.value = NULL;

    program->parameters.code_type = EBPF_CODE_NONE;

    return_value = ebpf_program_load_providers(program);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(local_program_name.value);
    ebpf_free(local_section_name.value);
    ebpf_free(local_file_name.value);
    EBPF_RETURN_RESULT(return_value);
}

_Ret_notnull_ const ebpf_program_parameters_t*
ebpf_program_get_parameters(_In_ const ebpf_program_t* program)
{
    return &program->parameters;
}

_Ret_notnull_ const ebpf_program_type_t*
ebpf_program_type_uuid(_In_ const ebpf_program_t* program)
{
    return &ebpf_program_get_parameters(program)->program_type;
}

_Ret_notnull_ const ebpf_attach_type_t*
ebpf_expected_attach_type(_In_ const ebpf_program_t* program)
{
    return &ebpf_program_get_parameters(program)->expected_attach_type;
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_associate_additional_map(ebpf_program_t* program, ebpf_map_t* map)
{
    EBPF_LOG_ENTRY();
    // First make sure the map can be associated.
    ebpf_result_t result = ebpf_map_associate_program(map, program);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }

    ebpf_lock_state_t state = ebpf_lock_lock(&program->lock);

    uint32_t map_count = program->count_of_maps + 1;
    ebpf_map_t** program_maps =
        ebpf_reallocate(program->maps, program->count_of_maps * sizeof(ebpf_map_t*), map_count * sizeof(ebpf_map_t*));
    if (program_maps == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    ebpf_object_acquire_reference((ebpf_core_object_t*)map);
    program_maps[map_count - 1] = map;
    program->maps = program_maps;
    program->count_of_maps = map_count;

Done:
    ebpf_lock_unlock(&program->lock, state);

    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_associate_maps(ebpf_program_t* program, ebpf_map_t** maps, uint32_t maps_count)
{
    EBPF_LOG_ENTRY();
    size_t index;
    ebpf_map_t** program_maps = ebpf_allocate(maps_count * sizeof(ebpf_map_t*));
    if (!program_maps)
        return EBPF_NO_MEMORY;

    memcpy(program_maps, maps, sizeof(ebpf_map_t*) * maps_count);

    // Before we acquire any references, make sure
    // all maps can be associated.
    ebpf_result_t result = EBPF_SUCCESS;
    for (index = 0; index < maps_count; index++) {
        ebpf_map_t* map = program_maps[index];
        result = ebpf_map_associate_program(map, program);
        if (result != EBPF_SUCCESS) {
            ebpf_free(program_maps);
            EBPF_RETURN_RESULT(result);
        }
    }

    // Now go through again and acquire references.
    program->maps = program_maps;
    program->count_of_maps = maps_count;
    for (index = 0; index < maps_count; index++) {
        ebpf_object_acquire_reference((ebpf_core_object_t*)program_maps[index]);
    }

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

static ebpf_result_t
_ebpf_program_load_machine_code(
    _Inout_ ebpf_program_t* program,
    _In_opt_ const void* code_context,
    _In_reads_(machine_code_size) const uint8_t* machine_code,
    size_t machine_code_size)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    uint8_t* local_machine_code = NULL;
    ebpf_memory_descriptor_t* local_code_memory_descriptor = NULL;

    ebpf_assert(program->parameters.code_type == EBPF_CODE_JIT || program->parameters.code_type == EBPF_CODE_NATIVE);

    if (program->parameters.code_type == EBPF_CODE_JIT) {
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

        program->code_or_vm.code.code_memory_descriptor = local_code_memory_descriptor;
        program->code_or_vm.code.code_pointer = local_machine_code;
        local_code_memory_descriptor = NULL;
    } else {
        ebpf_assert(machine_code_size == 0);
        if (code_context == NULL) {
            return_value = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        program->code_or_vm.native.module = code_context;
        program->code_or_vm.native.code_pointer = machine_code;
        // Acquire reference on the native module. This reference
        // will be released when the ebpf_program is freed.
        ebpf_native_acquire_reference((ebpf_native_module_binding_context_t*)code_context);
    }

    return_value = EBPF_SUCCESS;

Done:
    ebpf_unmap_memory(local_code_memory_descriptor);

    EBPF_RETURN_RESULT(return_value);
}

static ebpf_result_t
_ebpf_program_register_helpers(_In_ const ebpf_program_t* program)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    size_t index = 0;

    ebpf_assert(program->code_or_vm.vm != NULL);

    for (index = 0; index < program->helper_function_count; index++) {
        uint32_t helper_function_id = program->helper_function_ids[index];
        void* helper = NULL;

        result = _ebpf_program_get_helper_function_address(program, helper_function_id, (uint64_t*)&helper);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
        if (helper == NULL)
            continue;

#if !defined(CONFIG_BPF_JIT_ALWAYS_ON)
        if (ubpf_register(program->code_or_vm.vm, (unsigned int)index, NULL, (void*)helper) < 0) {
            EBPF_LOG_MESSAGE_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_PROGRAM, "ubpf_register failed", index);
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
#endif
    }

Exit:
    EBPF_RETURN_RESULT(result);
}

#if !defined(CONFIG_BPF_JIT_ALWAYS_ON)
static ebpf_result_t
_ebpf_program_load_byte_code(
    _Inout_ ebpf_program_t* program, _In_ const ebpf_instruction_t* instructions, size_t instruction_count)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    char* error_message = NULL;

    if (program->parameters.code_type != EBPF_CODE_EBPF) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "_ebpf_program_load_byte_code program->parameters.code_type must be EBPF_CODE_EBPF",
            program->parameters.code_type);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // ubpf currently requires the byte count to fit in a uint32_t.
    if (instruction_count > UINT32_MAX / sizeof(ebpf_instruction_t)) {
        return_value = EBPF_PROGRAM_TOO_LARGE;
        goto Done;
    }

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

    ubpf_set_error_print(program->code_or_vm.vm, ebpf_log_function);

    return_value = _ebpf_program_register_helpers(program);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    if (ubpf_load(
            program->code_or_vm.vm,
            instructions,
            (uint32_t)(instruction_count * sizeof(ebpf_instruction_t)),
            &error_message) != 0) {
        EBPF_LOG_MESSAGE_STRING(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_PROGRAM, "ubpf_load failed", error_message);
        ebpf_free(error_message);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

Done:
    if (return_value != EBPF_SUCCESS) {
        if (program->code_or_vm.vm)
            ubpf_destroy(program->code_or_vm.vm);
        program->code_or_vm.vm = NULL;
    }

    EBPF_RETURN_RESULT(return_value);
}
#endif

_Must_inspect_result_ ebpf_result_t
ebpf_program_load_code(
    _Inout_ ebpf_program_t* program,
    ebpf_code_type_t code_type,
    _In_opt_ const void* code_context,
    _In_reads_(code_size) const uint8_t* code,
    size_t code_size)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    program->parameters.code_type = code_type;
    ebpf_assert(
        (code_type == EBPF_CODE_NATIVE && code_context != NULL) ||
        (code_type != EBPF_CODE_NATIVE && code_context == NULL));
    if (program->parameters.code_type == EBPF_CODE_JIT || program->parameters.code_type == EBPF_CODE_NATIVE)
        result = _ebpf_program_load_machine_code(program, code_context, code, code_size);
    else if (program->parameters.code_type == EBPF_CODE_EBPF)
#if !defined(CONFIG_BPF_JIT_ALWAYS_ON)
        result = _ebpf_program_load_byte_code(
            program, (const ebpf_instruction_t*)code, code_size / sizeof(ebpf_instruction_t));
#else
        result = EBPF_BLOCKED_BY_POLICY;
#endif
    else {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "ebpf_program_load_code unknown program->parameters.code_type",
            program->parameters.code_type);

        result = EBPF_INVALID_ARGUMENT;
    }
    EBPF_RETURN_RESULT(result);
}

typedef struct _ebpf_program_tail_call_state
{
    const ebpf_program_t* next_program;
    uint32_t count;
} ebpf_program_tail_call_state_t;

_Must_inspect_result_ ebpf_result_t
ebpf_program_set_tail_call(_In_ const ebpf_program_t* next_program)
{
    // High volume call - Skip entry/exit logging.
    ebpf_result_t result;
    ebpf_program_tail_call_state_t* state = NULL;
    result = ebpf_state_load(_ebpf_program_state_index, (uintptr_t*)&state);
    if (result != EBPF_SUCCESS)
        return result;

    if (state == NULL)
        return EBPF_INVALID_ARGUMENT;

    if (state->count == MAX_TAIL_CALL_CNT) {
        return EBPF_NO_MORE_TAIL_CALLS;
    }

    state->next_program = next_program;

    return EBPF_SUCCESS;
}

void
ebpf_program_invoke(_In_ const ebpf_program_t* program, _Inout_ void* context, _Out_ uint32_t* result)
{
    // High volume call - Skip entry/exit logging.
    ebpf_program_tail_call_state_t state = {0};
    const ebpf_program_t* current_program = program;

    if (!program || program->invalidated) {
        *result = 0;
        return;
    }

    if (!ebpf_state_store(_ebpf_program_state_index, (uintptr_t)&state) == EBPF_SUCCESS) {
        *result = 0;
        return;
    }

    for (state.count = 0; state.count < MAX_TAIL_CALL_CNT; state.count++) {
        if (current_program->parameters.code_type == EBPF_CODE_JIT ||
            current_program->parameters.code_type == EBPF_CODE_NATIVE) {
            ebpf_program_entry_point_t function_pointer;
            function_pointer = (ebpf_program_entry_point_t)(current_program->code_or_vm.code.code_pointer);
            *result = (function_pointer)(context);
        } else {
#if !defined(CONFIG_BPF_JIT_ALWAYS_ON)
            uint64_t out_value;
            int ret = (uint32_t)(ubpf_exec(current_program->code_or_vm.vm, context, 1024, &out_value));
            if (ret < 0) {
                *result = ret;
            } else {
                *result = (uint32_t)(out_value);
            }
#else
            *result = 0;
#endif
        }

        if (state.count != 0) {
            ebpf_object_release_reference((ebpf_core_object_t*)current_program);
            current_program = NULL;
        }

        if (state.next_program == NULL) {
            break;
        } else {
            current_program = state.next_program;
            state.next_program = NULL;
        }
    }

    ebpf_assert_success(ebpf_state_store(_ebpf_program_state_index, 0));
}

static ebpf_result_t
_ebpf_program_get_helper_function_address(
    _In_ const ebpf_program_t* program, const uint32_t helper_function_id, uint64_t* address)
{
    ebpf_result_t return_value;
    void* function_address;
    EBPF_LOG_ENTRY();

    if (helper_function_id > EBPF_MAX_GENERAL_HELPER_FUNCTION) {
        if (!program->trampoline_table) {
            EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
        }
        return_value = ebpf_get_trampoline_function(program->trampoline_table, helper_function_id, &function_address);
        if (return_value != EBPF_SUCCESS)
            EBPF_RETURN_RESULT(return_value);

        *address = (uint64_t)function_address;
    } else {
        // First check if the extension has provided a new implementation of
        // the global helper function.
        if (program->global_helper_trampoline_table) {
            return_value = ebpf_get_trampoline_function(
                program->global_helper_trampoline_table, helper_function_id, &function_address);
            if (return_value == EBPF_SUCCESS) {
                // Found an entry.
                *address = (uint64_t)function_address;
                EBPF_RETURN_RESULT(EBPF_SUCCESS);
            }
        }
        ebpf_assert(program->general_helper_provider_data != NULL);
        _Analysis_assume_(program->general_helper_provider_data != NULL);
        ebpf_program_data_t* general_helper_program_data =
            (ebpf_program_data_t*)program->general_helper_provider_data->data;

        ebpf_assert(general_helper_program_data != NULL);
        _Analysis_assume_(general_helper_program_data != NULL);

        ebpf_helper_function_addresses_t* general_helper_function_addresses =
            general_helper_program_data->helper_function_addresses;

        ebpf_assert(general_helper_function_addresses != NULL);
        _Analysis_assume_(general_helper_function_addresses != NULL);

        if (helper_function_id > general_helper_function_addresses->helper_function_count) {
            return EBPF_INVALID_ARGUMENT;
        }
        *address = general_helper_function_addresses->helper_function_address[helper_function_id];
    }

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_get_helper_function_addresses(
    _In_ const ebpf_program_t* program, size_t addresses_count, _Out_writes_(addresses_count) uint64_t* addresses)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;

    if (program->helper_function_count > addresses_count) {
        result = EBPF_INSUFFICIENT_BUFFER;
        goto Exit;
    }

    for (uint32_t index = 0; index < program->helper_function_count; index++) {
        result =
            _ebpf_program_get_helper_function_address(program, program->helper_function_ids[index], &addresses[index]);
        if (result != EBPF_SUCCESS)
            break;
    }

Exit:
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_set_helper_function_ids(
    _Inout_ ebpf_program_t* program,
    const size_t helper_function_count,
    _In_reads_(helper_function_count) const uint32_t* helper_function_ids)
{
    EBPF_LOG_ENTRY();

    ebpf_result_t result = EBPF_SUCCESS;

    if (program->helper_function_ids != NULL) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "ebpf_program_set_helper_function_ids - helper function IDs already set");
        // Helper function IDs already set.
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (helper_function_count == 0)
        goto Exit;

    program->helper_function_count = helper_function_count;
    program->helper_function_ids = ebpf_allocate(sizeof(uint32_t) * helper_function_count);
    if (program->helper_function_ids == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    for (size_t index = 0; index < helper_function_count; index++)
        program->helper_function_ids[index] = helper_function_ids[index];

Exit:
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_get_program_info(_In_ const ebpf_program_t* program, _Outptr_ ebpf_program_info_t** program_info)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_data_t* program_data = NULL;
    ebpf_program_data_t* general_helper_program_data = NULL;
    ebpf_program_info_t* local_program_info = NULL;
    uint32_t total_count_of_helpers = 0;
    uint32_t helper_index = 0;

    ebpf_assert(program_info);
    *program_info = NULL;

    if (program->invalidated) {
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Exit;
    }

    if (!program->info_extension_provider_data) {
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Exit;
    }
    program_data = (ebpf_program_data_t*)program->info_extension_provider_data->data;

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

    EBPF_RETURN_RESULT(result);
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
ebpf_program_attach_link(_Inout_ ebpf_program_t* program, _Inout_ ebpf_link_t* link)
{
    EBPF_LOG_ENTRY();
    // Acquire "attach" reference on the link object.
    ebpf_object_acquire_reference((ebpf_core_object_t*)link);

    // Insert the link in the attach list.
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&program->lock);
    ebpf_list_insert_tail(&program->links, &((ebpf_core_object_t*)link)->object_list_entry);
    program->link_count++;
    ebpf_lock_unlock(&program->lock, state);
    EBPF_RETURN_VOID();
}

void
ebpf_program_detach_link(_Inout_ ebpf_program_t* program, _Inout_ ebpf_link_t* link)
{
    EBPF_LOG_ENTRY();
    // Remove the link from the attach list.
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&program->lock);
    ebpf_list_remove_entry(&((ebpf_core_object_t*)link)->object_list_entry);
    program->link_count--;
    ebpf_lock_unlock(&program->lock, state);

    // Release the "attach" reference.
    ebpf_object_release_reference((ebpf_core_object_t*)link);
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_get_info(
    _In_ const ebpf_program_t* program,
    _In_reads_(*info_size) const uint8_t* input_buffer,
    _Out_writes_to_(*info_size, *info_size) uint8_t* output_buffer,
    _Inout_ uint16_t* info_size)
{
    EBPF_LOG_ENTRY();
    const struct bpf_prog_info* input_info = (const struct bpf_prog_info*)input_buffer;
    struct bpf_prog_info* output_info = (struct bpf_prog_info*)output_buffer;
    if (*info_size < sizeof(*output_info)) {
        EBPF_RETURN_RESULT(EBPF_INSUFFICIENT_BUFFER);
    }

    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_id_t* map_ids = (ebpf_id_t*)input_info->map_ids;
    if ((input_info->map_ids != 0) && (input_info->nr_map_ids > 0) && (program->count_of_maps > 0)) {
        // Fill in map ids before we overwrite the info buffer.
        uint32_t max_nr_map_ids = input_info->nr_map_ids;
        size_t length = max_nr_map_ids * sizeof(ebpf_id_t);

        __try {
            ebpf_probe_for_write(map_ids, length, sizeof(ebpf_id_t));

            for (uint32_t i = 0; i < program->count_of_maps; i++) {
                if (i == max_nr_map_ids) {
                    // No more space left.
                    EBPF_RETURN_RESULT(EBPF_INVALID_POINTER);
                } else {
                    ebpf_map_t* map = program->maps[i];
                    map_ids[i] = ebpf_map_get_id(map);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            EBPF_RETURN_RESULT(EBPF_INVALID_POINTER);
        }
    }

    memset(output_info, 0, sizeof(*output_info));
    output_info->id = program->object.id;
    strncpy_s(
        output_info->name,
        sizeof(output_info->name),
        (char*)program->parameters.program_name.value,
        program->parameters.program_name.length);
    output_info->nr_map_ids = program->count_of_maps;
    output_info->map_ids = (uintptr_t)map_ids;
    output_info->type = _ebpf_program_get_bpf_prog_type(program);
    output_info->type_uuid = *ebpf_program_type_uuid(program);
    output_info->attach_type_uuid = *ebpf_expected_attach_type(program);
    output_info->pinned_path_count = program->object.pinned_path_count;
    output_info->link_count = program->link_count;

    *info_size = sizeof(*output_info);
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_create_and_initialize(
    _In_ const ebpf_program_parameters_t* parameters, _Out_ ebpf_handle_t* program_handle)
{
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;

    retval = ebpf_program_create(&program);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_program_initialize(program, parameters);
    if (retval != EBPF_SUCCESS)
        goto Done;

    retval = ebpf_handle_create(program_handle, (ebpf_base_object_t*)program);
    if (retval != EBPF_SUCCESS)
        goto Done;

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)program);
    return retval;
}
