// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf_async.h"
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

#include <stdlib.h>

static size_t _ebpf_program_state_index = MAXUINT64;
#define EBPF_MAX_HASH_SIZE 128
#define EBPF_HASH_ALGORITHM L"SHA256"

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
    bpf_prog_type_t bpf_prog_type;

    // Program type specific helper function count.
    uint32_t program_type_specific_helper_function_count;
    // Global helper function count implemented by the extension.
    uint32_t global_helper_function_count;

    ebpf_trampoline_table_t* trampoline_table;

    // Array of helper function ids referred by this program.
    size_t helper_function_count;
    uint32_t* helper_function_ids;

    ebpf_epoch_work_item_t* cleanup_work_item;

    // Lock protecting the fields below.
    ebpf_lock_t lock;

    _Guarded_by_(lock) ebpf_list_entry_t links;
    _Guarded_by_(lock) uint32_t link_count;
    _Guarded_by_(lock) ebpf_map_t** maps;
    _Guarded_by_(lock) uint32_t count_of_maps;

    _Guarded_by_(lock) ebpf_helper_function_addresses_changed_callback_t helper_function_addresses_changed_callback;
    _Guarded_by_(lock) void* helper_function_addresses_changed_context;
} ebpf_program_t;

static ebpf_result_t
_ebpf_program_update_helpers(_Inout_ ebpf_program_t* program);

static ebpf_result_t
_ebpf_program_update_interpret_helpers(_Inout_ ebpf_program_t* program, _Inout_ void* context);

static ebpf_result_t
_ebpf_program_update_jit_helpers(_Inout_ ebpf_program_t* program, _Inout_ void* context);

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

static ebpf_result_t
_ebpf_program_initialize_or_verify_program_info_hash(_Inout_ ebpf_program_t* program);

static ebpf_result_t
_ebpf_program_program_info_provider_changed(
    _In_ const void* client_binding_context, _In_opt_ const ebpf_extension_data_t* provider_data)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_program_t* program = (ebpf_program_t*)client_binding_context;

    if (provider_data == NULL) {
        // Detach
        // Extension is detaching. Program will get invalidated.
        program->info_extension_provider_data = NULL;
        return_value = EBPF_SUCCESS;
        goto Exit;
    } else {
        // Attach
        program->info_extension_provider_data = provider_data;

        const ebpf_helper_function_addresses_t* helper_function_addresses = NULL;
        const ebpf_helper_function_addresses_t* global_helper_function_addresses = NULL;

        ebpf_program_data_t* program_data = (ebpf_program_data_t*)provider_data->data;
        if (program_data == NULL) {
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_PROGRAM,
                "An extension cannot have empty program_data",
                program->parameters.program_type);
            // An extension cannot have empty program_data.
            return_value = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        if (program_data->required_irql > HIGH_LEVEL) {
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_PROGRAM,
                "An extension cannot have required_irql higher than HIGH_LEVEL",
                program->parameters.program_type);
            return_value = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        helper_function_addresses = program_data->program_type_specific_helper_function_addresses;
        global_helper_function_addresses = program_data->global_helper_function_addresses;

        if ((program->program_type_specific_helper_function_count > 0) &&
            (helper_function_addresses->helper_function_count !=
             program->program_type_specific_helper_function_count)) {

            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_PROGRAM,
                "A program info provider cannot modify helper function count upon reload",
                program->parameters.program_type);
            // A program info provider cannot modify helper function count upon reload.
            return_value = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        if ((program->global_helper_function_count > 0) &&
            (global_helper_function_addresses->helper_function_count != program->global_helper_function_count)) {

            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_PROGRAM,
                "A program info provider cannot modify global helper function count upon reload",
                program->parameters.program_type);
            // A program info provider cannot modify helper function count upon reload.
            return_value = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        return_value = _ebpf_program_initialize_or_verify_program_info_hash(program);
        if (return_value != EBPF_SUCCESS) {
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_PROGRAM,
                "The program info used to verify the program doesn't match the program info provided by the "
                "extension",
                program->parameters.program_type);
            goto Exit;
        }

        return_value = _ebpf_program_update_helpers(program);
        if (return_value != EBPF_SUCCESS) {
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_PROGRAM, "Failed to update helpers for program");
            goto Exit;
        }

        program->program_type_specific_helper_function_count =
            helper_function_addresses ? helper_function_addresses->helper_function_count : 0;
        program->global_helper_function_count =
            global_helper_function_addresses ? global_helper_function_addresses->helper_function_count : 0;
        program->bpf_prog_type = program_data->program_info->program_type_descriptor.bpf_prog_type;
        return_value = EBPF_SUCCESS;
    }

Exit:

    if (return_value != EBPF_SUCCESS) {
        program->info_extension_provider_data = NULL;
    }

    EBPF_RETURN_RESULT(return_value);
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
    if (!program) {
        EBPF_RETURN_VOID();
    }

    // Detach from all the attach points.
    _ebpf_program_detach_links(program);
    ebpf_assert(ebpf_list_is_empty(&program->links));

    for (index = 0; index < program->count_of_maps; index++) {
        ebpf_object_release_reference((ebpf_core_object_t*)program->maps[index]);
    }

    ebpf_epoch_work_item_t* cleanup_work_item = program->cleanup_work_item;
    program->cleanup_work_item = NULL;

    ebpf_epoch_schedule_work_item(cleanup_work_item);
    EBPF_RETURN_VOID();
}

static ebpf_program_type_t
_ebpf_program_get_program_type(_In_ const ebpf_core_object_t* object)
{
    return ebpf_program_type_uuid((const ebpf_program_t*)object);
}

static const bpf_prog_type_t
_ebpf_program_get_bpf_prog_type(_In_ const ebpf_program_t* program)
{
    return program->bpf_prog_type;
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
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
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
    ebpf_free((void*)program->parameters.program_info_hash);

    ebpf_free(program->maps);

    ebpf_free_trampoline_table(program->trampoline_table);

    ebpf_free(program->helper_function_ids);

    ebpf_epoch_cancel_work_item(program->cleanup_work_item);
    ebpf_free(program);
    EBPF_RETURN_VOID();
}

static ebpf_result_t
_ebpf_program_load_providers(_Inout_ ebpf_program_t* program)
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
    if (!general_helper_program_data ||
        general_helper_program_data->program_type_specific_helper_function_addresses == NULL) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "general_helper_program_data->program_type_specific_helper_function_addresses can not be NULL",
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

    local_program = (ebpf_program_t*)ebpf_allocate_with_tag(sizeof(ebpf_program_t), EBPF_POOL_TAG_PROGRAM);
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

    local_program->bpf_prog_type = BPF_PROG_TYPE_UNSPEC;

    *program = local_program;
    local_program = NULL;
    retval = EBPF_SUCCESS;

Done:
    if (local_program) {
        _ebpf_program_epoch_free(local_program);
    }

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
    uint8_t* local_program_info_hash = NULL;

    ebpf_lock_state_t state = ebpf_lock_lock(&program->lock);
    bool lock_held = true;

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
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_duplicate_utf8_string(&local_section_name, &program_parameters->section_name);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_duplicate_utf8_string(&local_file_name, &program_parameters->file_name);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    if (program_parameters->program_info_hash_length > 0) {
        local_program_info_hash =
            ebpf_allocate_with_tag(program_parameters->program_info_hash_length, EBPF_POOL_TAG_PROGRAM);
        if (!local_program_info_hash) {
            return_value = EBPF_NO_MEMORY;
            goto Done;
        }
        memcpy(
            local_program_info_hash,
            program_parameters->program_info_hash,
            program_parameters->program_info_hash_length);
    }

    program->parameters = *program_parameters;

    program->parameters.program_name = local_program_name;
    local_program_name.value = NULL;
    program->parameters.section_name = local_section_name;
    local_section_name.value = NULL;
    program->parameters.file_name = local_file_name;
    local_file_name.value = NULL;

    program->parameters.code_type = EBPF_CODE_NONE;
    program->parameters.program_info_hash = local_program_info_hash;
    local_program_info_hash = NULL;

    ebpf_lock_unlock(&program->lock, state);
    lock_held = false;

    return_value = _ebpf_program_load_providers(program);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(local_program_info_hash);
    ebpf_free(local_program_name.value);
    ebpf_free(local_section_name.value);
    ebpf_free(local_file_name.value);
    if (lock_held) {
        ebpf_lock_unlock(&program->lock, state);
    }
    EBPF_RETURN_RESULT(return_value);
}

ebpf_program_type_t
ebpf_program_type_uuid(_In_ const ebpf_program_t* program)
{
    ebpf_lock_state_t state = ebpf_lock_lock((ebpf_lock_t*)&program->lock);
    ebpf_program_type_t return_value = program->parameters.program_type;
    ebpf_lock_unlock((ebpf_lock_t*)&program->lock, state);
    return return_value;
}

ebpf_attach_type_t
ebpf_expected_attach_type(_In_ const ebpf_program_t* program)
{
    ebpf_lock_state_t state = ebpf_lock_lock((ebpf_lock_t*)&program->lock);
    ebpf_attach_type_t return_value = program->parameters.expected_attach_type;
    ebpf_lock_unlock((ebpf_lock_t*)&program->lock, state);
    return return_value;
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
    ebpf_result_t result = EBPF_SUCCESS;
    EBPF_LOG_ENTRY();

    size_t index;
    ebpf_map_t** program_maps = ebpf_allocate_with_tag(maps_count * sizeof(ebpf_map_t*), EBPF_POOL_TAG_PROGRAM);
    if (!program_maps) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    memcpy(program_maps, maps, sizeof(ebpf_map_t*) * maps_count);

    // Before we acquire any references, make sure
    // all maps can be associated.
    for (index = 0; index < maps_count; index++) {
        ebpf_map_t* map = program_maps[index];
        result = ebpf_map_associate_program(map, program);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }
    }

    ebpf_lock_state_t state = ebpf_lock_lock(&program->lock);
    // Now go through again and acquire references.
    program->maps = program_maps;
    program_maps = NULL;
    program->count_of_maps = maps_count;
    for (index = 0; index < maps_count; index++) {
        ebpf_object_acquire_reference((ebpf_core_object_t*)program->maps[index]);
    }
    ebpf_lock_unlock(&program->lock, state);

Done:
    ebpf_free(program_maps);

    EBPF_RETURN_RESULT(result);
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
        program->helper_function_addresses_changed_callback = _ebpf_program_update_jit_helpers;
        program->helper_function_addresses_changed_context = program;
        return_value = _ebpf_program_update_helpers(program);
        if (return_value != EBPF_SUCCESS) {
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_PROGRAM, "Failed to update helpers for program");
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
_ebpf_program_update_helpers(_Inout_ ebpf_program_t* program)
{
    if (program->helper_function_addresses_changed_callback != NULL) {
        return program->helper_function_addresses_changed_callback(
            program, program->helper_function_addresses_changed_context);
    } else {
        return EBPF_SUCCESS;
    }
}

static ebpf_result_t
_ebpf_program_update_interpret_helpers(_Inout_ ebpf_program_t* program, _Inout_ void* context)
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(context);
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
        if (helper == NULL) {
            continue;
        }

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
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

static ebpf_result_t
_ebpf_program_update_jit_helpers(_Inout_ ebpf_program_t* program, _Inout_ void* context)
{
    ebpf_result_t return_value;
    UNREFERENCED_PARAMETER(context);
    ebpf_program_data_t* program_data = NULL;
    const ebpf_helper_function_addresses_t* helper_function_addresses = NULL;
    const ebpf_helper_function_addresses_t* global_helper_function_addresses = NULL;

    size_t total_helper_count = 0;
    ebpf_helper_function_addresses_t* total_helper_function_addresses = NULL;
    uint32_t* total_helper_function_ids = NULL;
    bool provider_data_referenced = false;

    if (!program->info_extension_client || !ebpf_extension_reference_provider_data(program->info_extension_client)) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "The extension is not loaded for program type",
            program->parameters.program_type);
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Exit;
    }
    provider_data_referenced = true;
    program_data = (ebpf_program_data_t*)program->info_extension_provider_data->data;
    helper_function_addresses = program_data->program_type_specific_helper_function_addresses;
    global_helper_function_addresses = program_data->global_helper_function_addresses;

    if (helper_function_addresses != NULL || global_helper_function_addresses != NULL) {
        const ebpf_program_info_t* program_info = program_data->program_info;
        const ebpf_helper_function_prototype_t* helper_prototypes = NULL;
        ebpf_assert(program_info != NULL);
        _Analysis_assume_(program_info != NULL);
        if ((helper_function_addresses != NULL && program_info->count_of_program_type_specific_helpers !=
                                                      helper_function_addresses->helper_function_count) ||
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

        // Merge the helper function addresses into a single array.
        return_value = ebpf_safe_size_t_add(
            program->program_type_specific_helper_function_count,
            program->global_helper_function_count,
            &total_helper_count);
        if (return_value != EBPF_SUCCESS) {
            goto Exit;
        }

        total_helper_function_addresses =
            (ebpf_helper_function_addresses_t*)ebpf_allocate(sizeof(ebpf_helper_function_addresses_t));
        if (total_helper_function_addresses == NULL) {
            return_value = EBPF_NO_MEMORY;
            goto Exit;
        }
        total_helper_function_addresses->helper_function_count = (uint32_t)total_helper_count;
        total_helper_function_addresses->helper_function_address =
            (uint64_t*)ebpf_allocate(sizeof(uint64_t) * total_helper_count);
        if (total_helper_function_addresses->helper_function_address == NULL) {
            return_value = EBPF_NO_MEMORY;
            goto Exit;
        }

        if (!program->trampoline_table) {
            // Program info provider is being loaded for the first time. Allocate trampoline table.
            return_value = ebpf_allocate_trampoline_table(total_helper_count, &program->trampoline_table);
            if (return_value != EBPF_SUCCESS) {
                goto Exit;
            }
        }

        __analysis_assume(total_helper_count > 0);
        total_helper_function_ids = (uint32_t*)ebpf_allocate(sizeof(uint32_t) * total_helper_count);
        if (total_helper_function_ids == NULL) {
            return_value = EBPF_NO_MEMORY;
            goto Exit;
        }

        if (helper_function_addresses != NULL) {
            helper_prototypes = program_info->program_type_specific_helper_prototype;
            if (helper_prototypes == NULL) {
                EBPF_LOG_MESSAGE_GUID(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_PROGRAM,
                    "program_info->program_type_specific_helper_prototype can not be NULL",
                    program->parameters.program_type);
                return_value = EBPF_INVALID_ARGUMENT;
                goto Exit;
            }

#pragma warning(push)
#pragma warning(disable : 6386) // Buffer overrun while writing to 'total_helper_function_ids'.
            for (uint32_t index = 0; index < program->program_type_specific_helper_function_count; index++) {
                total_helper_function_ids[index] = helper_prototypes[index].helper_id;
                total_helper_function_addresses->helper_function_address[index] =
                    helper_function_addresses->helper_function_address[index];
            }
        }
#pragma warning(pop)

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

#pragma warning(push)
#pragma warning( \
    disable : 6386) // Buffer overrun while writing to 'total_helper_function_addresses->helper_function_address'
            for (uint32_t index = program->program_type_specific_helper_function_count; index < total_helper_count;
                 index++) {
                uint32_t global_helper_index = index - program->program_type_specific_helper_function_count;
                total_helper_function_ids[index] = helper_prototypes[global_helper_index].helper_id;
                total_helper_function_addresses->helper_function_address[index] =
                    global_helper_function_addresses->helper_function_address[global_helper_index];
            }
        }
#pragma warning(pop)

        return_value = ebpf_update_trampoline_table(
            program->trampoline_table,
            (uint32_t)total_helper_count,
            total_helper_function_ids,
            total_helper_function_addresses);
        if (return_value != EBPF_SUCCESS) {
            goto Exit;
        }
    }

    return_value = EBPF_SUCCESS;

Exit:
    ebpf_free(total_helper_function_ids);
    if (total_helper_function_addresses != NULL) {
        ebpf_free(total_helper_function_addresses->helper_function_address);
        ebpf_free(total_helper_function_addresses);
    }

    if (provider_data_referenced) {
        ebpf_extension_dereference_provider_data(program->info_extension_client);
    }

    return return_value;
}

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
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

    program->helper_function_addresses_changed_callback = _ebpf_program_update_interpret_helpers;
    program->helper_function_addresses_changed_context = NULL;

    return_value = _ebpf_program_update_helpers(program);
    if (return_value != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_PROGRAM, "Failed to update helpers for program");
        goto Done;
    }

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
        if (program->code_or_vm.vm) {
            ubpf_destroy(program->code_or_vm.vm);
        }
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

    switch (program->parameters.code_type) {

    case EBPF_CODE_JIT:
    case EBPF_CODE_NATIVE:
        result = _ebpf_program_load_machine_code(program, code_context, code, code_size);
        break;

    case EBPF_CODE_EBPF:
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
        result = _ebpf_program_load_byte_code(
            program, (const ebpf_instruction_t*)code, code_size / sizeof(ebpf_instruction_t));
#else
        result = EBPF_BLOCKED_BY_POLICY;
#endif
        break;

    default: {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "ebpf_program_load_code unknown program->parameters.code_type",
            program->parameters.code_type);

        result = EBPF_INVALID_ARGUMENT;
    }
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
    if (result != EBPF_SUCCESS) {
        return result;
    }

    if (state == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (state->count == MAX_TAIL_CALL_CNT) {
        return EBPF_NO_MORE_TAIL_CALLS;
    }

    state->next_program = next_program;

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_reference_providers(_Inout_ ebpf_program_t* program)
{
    if (!program->info_extension_client || !ebpf_extension_reference_provider_data(program->info_extension_client)) {
        return EBPF_EXTENSION_FAILED_TO_LOAD;
    }
    return EBPF_SUCCESS;
}

void
ebpf_program_dereference_providers(_Inout_ ebpf_program_t* program)
{
    ebpf_extension_dereference_provider_data(program->info_extension_client);
}

void
ebpf_program_invoke(
    _In_ const ebpf_program_t* program,
    _Inout_ void* context,
    _Out_ uint32_t* result,
    _In_ const ebpf_execution_context_state_t* execution_state)
{
    // High volume call - Skip entry/exit logging.
    ebpf_program_tail_call_state_t state = {0};
    const ebpf_program_t* current_program = program;

    bool program_state_stored = false;

    if (!ebpf_state_store(_ebpf_program_state_index, (uintptr_t)&state, execution_state) == EBPF_SUCCESS) {
        *result = 0;
        goto Done;
    }

    program_state_stored = true;

    for (state.count = 0; state.count < MAX_TAIL_CALL_CNT; state.count++) {

        if (current_program->parameters.code_type == EBPF_CODE_JIT ||
            current_program->parameters.code_type == EBPF_CODE_NATIVE) {
            ebpf_program_entry_point_t function_pointer;
            function_pointer = (ebpf_program_entry_point_t)(current_program->code_or_vm.code.code_pointer);
            *result = (function_pointer)(context);
        } else {
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
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

Done:
    if (program_state_stored) {
        ebpf_assert_success(ebpf_state_store(_ebpf_program_state_index, 0, execution_state));
    }
}

static ebpf_result_t
_ebpf_program_get_helper_function_address(
    _In_ const ebpf_program_t* program, const uint32_t helper_function_id, uint64_t* address)
{
    ebpf_result_t return_value;
    uint64_t* function_address = NULL;
    ebpf_program_data_t* program_data = NULL;
    ebpf_program_data_t* general_program_data = NULL;

    EBPF_LOG_ENTRY();

    bool provider_data_referenced = false;
    bool use_trampoline = false;
    bool found = false;

    if (!program->info_extension_client || !ebpf_extension_reference_provider_data(program->info_extension_client)) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "The extension is not loaded for program type",
            program->parameters.program_type);
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }
    provider_data_referenced = true;

    program_data = (ebpf_program_data_t*)program->info_extension_provider_data->data;
    general_program_data = (ebpf_program_data_t*)program->general_helper_provider_data->data;

    use_trampoline = program->parameters.code_type == EBPF_CODE_JIT;
    if (use_trampoline && !program->trampoline_table) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "The trampoline table is not initialized for JIT program");
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // First check the trampoline table for the helper function.
    if (use_trampoline) {
        return_value = ebpf_get_trampoline_function(program->trampoline_table, helper_function_id, &function_address);
        if (return_value == EBPF_SUCCESS) {
            found = true;
        }
    }

    if (helper_function_id < EBPF_MAX_GENERAL_HELPER_FUNCTION) {
        // Check the general helper function table of the program type.
        if (!found) {
            for (size_t index = 0; index < program_data->program_info->count_of_global_helpers; index++) {
                if (program_data->program_info->global_helper_prototype[index].helper_id == helper_function_id) {
                    function_address =
                        (void*)program_data->global_helper_function_addresses->helper_function_address[index];
                    found = true;
                    break;
                }
            }
        }

        // Check the general helper function table of the general program type.
        if (!found) {
            for (size_t index = 0; index < general_program_data->program_info->count_of_program_type_specific_helpers;
                 index++) {
                if (general_program_data->program_info->program_type_specific_helper_prototype[index].helper_id ==
                    helper_function_id) {
                    function_address = (void*)general_program_data->program_type_specific_helper_function_addresses
                                           ->helper_function_address[index];
                    found = true;
                    break;
                }
            }
        }
    } else {
        // Check the program type specific helper function table of the program type.
        if (!found) {
            for (size_t index = 0; index < program_data->program_info->count_of_program_type_specific_helpers;
                 index++) {
                if (program_data->program_info->program_type_specific_helper_prototype[index].helper_id ==
                    helper_function_id) {
                    function_address = (void*)program_data->program_type_specific_helper_function_addresses
                                           ->helper_function_address[index];
                    found = true;
                    break;
                }
            }
        }
    }

    if (!found) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    *address = (uint64_t)function_address;

    return_value = EBPF_SUCCESS;

Done:
    if (provider_data_referenced) {
        ebpf_extension_dereference_provider_data(program->info_extension_client);
    }
    EBPF_RETURN_RESULT(return_value);
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
        if (result != EBPF_SUCCESS) {
            break;
        }
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

    if (helper_function_count == 0) {
        goto Exit;
    }

    program->helper_function_count = helper_function_count;
    program->helper_function_ids =
        ebpf_allocate_with_tag(sizeof(uint32_t) * helper_function_count, EBPF_POOL_TAG_PROGRAM);
    if (program->helper_function_ids == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    for (size_t index = 0; index < helper_function_count; index++) {
        program->helper_function_ids[index] = helper_function_ids[index];
    }

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
    bool provider_data_referenced = false;

    ebpf_assert(program_info);
    *program_info = NULL;

    if (!program->info_extension_client || !ebpf_extension_reference_provider_data(program->info_extension_client)) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "The extension is not loaded for program type",
            program->parameters.program_type);
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Exit;
    }
    provider_data_referenced = true;
    program_data = (ebpf_program_data_t*)program->info_extension_provider_data->data;

    if (!program->general_helper_provider_data) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "General helper provider not loaded",
            program->parameters.program_type);
        result = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Exit;
    }
    general_helper_program_data = (ebpf_program_data_t*)program->general_helper_provider_data->data;

    total_count_of_helpers = program_data->program_info->count_of_program_type_specific_helpers +
                             general_helper_program_data->program_info->count_of_program_type_specific_helpers;
    if ((total_count_of_helpers < program_data->program_info->count_of_program_type_specific_helpers) ||
        (total_count_of_helpers < general_helper_program_data->program_info->count_of_program_type_specific_helpers)) {
        result = EBPF_ARITHMETIC_OVERFLOW;
        goto Exit;
    }

    // Allocate buffer and make a shallow copy of the program info.
    local_program_info =
        (ebpf_program_info_t*)ebpf_allocate_with_tag(sizeof(ebpf_program_info_t), EBPF_POOL_TAG_PROGRAM);
    if (local_program_info == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    local_program_info->program_type_descriptor = program_data->program_info->program_type_descriptor;
    local_program_info->count_of_program_type_specific_helpers = total_count_of_helpers;

    if (total_count_of_helpers > 0) {
        // Allocate buffer and make a shallow copy of the combined global and program-type specific helper function
        // prototypes.
        ebpf_helper_function_prototype_t* helper_prototype = (ebpf_helper_function_prototype_t*)ebpf_allocate_with_tag(
            total_count_of_helpers * sizeof(ebpf_helper_function_prototype_t), EBPF_POOL_TAG_PROGRAM);
        if (helper_prototype == NULL) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        local_program_info->program_type_specific_helper_prototype = helper_prototype;

        for (uint32_t index = 0; index < program_data->program_info->count_of_program_type_specific_helpers; index++) {
            __analysis_assume(helper_index < total_count_of_helpers);
            helper_prototype[helper_index++] =
                program_data->program_info->program_type_specific_helper_prototype[index];
        }

        for (uint32_t index = 0;
             index < general_helper_program_data->program_info->count_of_program_type_specific_helpers;
             index++) {
            __analysis_assume(helper_index < total_count_of_helpers);
            helper_prototype[helper_index++] =
                general_helper_program_data->program_info->program_type_specific_helper_prototype[index];
        }
    }

Exit:
    if (result == EBPF_SUCCESS) {
        *program_info = local_program_info;
        local_program_info = NULL;
    } else {
        ebpf_program_free_program_info(local_program_info);
    }

    if (provider_data_referenced) {
        ebpf_extension_dereference_provider_data(program->info_extension_client);
    }

    EBPF_RETURN_RESULT(result);
}

void
ebpf_program_free_program_info(_In_opt_ _Post_invalid_ ebpf_program_info_t* program_info)
{
    if (program_info != NULL) {
        ebpf_free((void*)program_info->program_type_specific_helper_prototype);
        ebpf_free((void*)program_info->global_helper_prototype);
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
    output_info->type_uuid = ebpf_program_type_uuid(program);
    output_info->attach_type_uuid = ebpf_expected_attach_type(program);
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
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_program_initialize(program, parameters);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_handle_create(program_handle, (ebpf_base_object_t*)program);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)program);
    return retval;
}

typedef struct _ebpf_helper_id_to_index
{
    uint32_t helper_id;
    uint32_t index;
} ebpf_helper_id_to_index_t;

int
_ebpf_helper_id_to_index_compare(const void* lhs, const void* rhs)
{
    const ebpf_helper_id_to_index_t* left = (const ebpf_helper_id_to_index_t*)lhs;
    const ebpf_helper_id_to_index_t* right = (const ebpf_helper_id_to_index_t*)rhs;
    return (left->helper_id < right->helper_id) ? -1 : (left->helper_id > right->helper_id) ? 1 : 0;
}

/**
 * @brief Compute the hash of the program info and compare it with the hash stored in the program. If the hash does not
 * match then the program was verified against the wrong program info. If the hash is not present then store the hash
 * in the program so it can be compared when the program information provider reattaches.
 *
 * Notes on why this works:
 * 1) The user application creates an ebpf_program_t object and sets the program type.
 * 2) During initialization, the program binds to the program information provider.
 * 3) During the attach callback, the program information is hashed and stored.
 * 4) The verifier then queries the program information from the ebpf_program_t object and uses it to verify the program
 * safety.
 * 5) If the program information provider is reattached, the program information is hashed and compared with the
 * hash stored in the program and the program is rejected if the hash does not match. This ensures that the program
 * information the verifier uses to verify the program safety is the same as the program information the program uses to
 * execute.
 *
 * @param[in] program Program to validate.
 * @param[in] program_info Program info to validate against.
 * @return EBPF_SUCCESS the program info hash matches.
 * @return EBPF_INVALID_ARGUMENT the program info hash does not match.
 */
static ebpf_result_t
_ebpf_program_initialize_or_verify_program_info_hash(_Inout_ ebpf_program_t* program)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_cryptographic_hash_t* cryptographic_hash = NULL;
    ebpf_helper_id_to_index_t* helper_id_to_index = NULL;
    ebpf_program_info_t* program_info = NULL;

    result = ebpf_program_get_program_info(program, &program_info);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    helper_id_to_index = (ebpf_helper_id_to_index_t*)ebpf_allocate_with_tag(
        program_info->count_of_program_type_specific_helpers * sizeof(ebpf_helper_id_to_index_t),
        EBPF_POOL_TAG_PROGRAM);
    if (helper_id_to_index == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    for (uint32_t index = 0; index < program_info->count_of_program_type_specific_helpers; index++) {
        helper_id_to_index[index].helper_id = program_info->program_type_specific_helper_prototype[index].helper_id;
        helper_id_to_index[index].index = index;
    }

    // Sort helper_id_to_index by helper_id.
    qsort(
        helper_id_to_index,
        program_info->count_of_program_type_specific_helpers,
        sizeof(ebpf_helper_id_to_index_t),
        _ebpf_helper_id_to_index_compare);

    result = ebpf_cryptographic_hash_create(EBPF_HASH_ALGORITHM, &cryptographic_hash);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Hash is performed over the following fields:
    // 1. Program type name.
    // 2. Context descriptor.
    // 3. Program type.
    // 4. BPF program type.
    // 5. Is_privileged flag.
    // 6. Count of helpers.
    // 7. For each program type specific helper (in helper id order).
    //   a. Helper id.
    //   b. Helper name.
    //   c. Helper return type.
    //   d. Helper argument types.

    // Note:
    // Order and fields being hashed is important. The order and fields being hashed must match the order and fields
    // being hashed in bpf2c. If new fields are added to the program info, then the hash must be updated to include the
    // new fields, both here and in bpf2c.

    result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_STR(cryptographic_hash, program_info->program_type_descriptor.name);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(
        cryptographic_hash, *program_info->program_type_descriptor.context_descriptor);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result =
        EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(cryptographic_hash, program_info->program_type_descriptor.program_type);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result =
        EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(cryptographic_hash, program_info->program_type_descriptor.bpf_prog_type);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result =
        EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(cryptographic_hash, program_info->program_type_descriptor.is_privileged);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result =
        EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(cryptographic_hash, program_info->count_of_program_type_specific_helpers);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    for (uint32_t i = 0; i < program_info->count_of_program_type_specific_helpers; i++) {
        uint32_t index = helper_id_to_index[i].index;
        result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(
            cryptographic_hash, program_info->program_type_specific_helper_prototype[index].helper_id);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_STR(
            cryptographic_hash, program_info->program_type_specific_helper_prototype[index].name);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(
            cryptographic_hash, program_info->program_type_specific_helper_prototype[index].return_type);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        for (uint32_t j = 0; j < EBPF_COUNT_OF(program_info->program_type_specific_helper_prototype[index].arguments);
             j++) {
            result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(
                cryptographic_hash, program_info->program_type_specific_helper_prototype[index].arguments[j]);
            if (result != EBPF_SUCCESS) {
                goto Exit;
            }
        }
    }

    uint8_t hash[EBPF_MAX_HASH_SIZE];
    size_t hash_length = EBPF_MAX_HASH_SIZE;
    size_t output_hash_length = 0;
    result = ebpf_cryptographic_hash_get_hash(cryptographic_hash, hash, hash_length, &output_hash_length);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (program->parameters.program_info_hash_length == 0) {
        // This is the first time the program info hash is being computed.
        uint8_t* new_hash = ebpf_allocate(output_hash_length);
        if (new_hash == NULL) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        program->parameters.program_info_hash = new_hash;
        program->parameters.program_info_hash_length = output_hash_length;
        memcpy((uint8_t*)program->parameters.program_info_hash, hash, output_hash_length);
    } else {
        if (output_hash_length != program->parameters.program_info_hash_length) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        if (memcmp(hash, program->parameters.program_info_hash, output_hash_length) != 0) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
    }

    result = EBPF_SUCCESS;

Exit:
    ebpf_free(helper_id_to_index);
    ebpf_cryptographic_hash_destroy(cryptographic_hash);
    ebpf_program_free_program_info((ebpf_program_info_t*)program_info);

    EBPF_RETURN_RESULT(result);
}

typedef struct _ebpf_program_test_run_context
{
    const ebpf_program_t* program;
    ebpf_program_data_t* program_data;
    void* context;
    ebpf_program_test_run_options_t* options;
    uint8_t required_irql;
    bool canceled;
    void* async_context;
    void* completion_context;
    ebpf_program_test_run_complete_callback_t completion_callback;
} ebpf_program_test_run_context_t;

static void
_ebpf_program_test_run_work_item(_Inout_opt_ void* work_item_context)
{
    _Analysis_assume_(work_item_context != NULL);

    ebpf_program_test_run_context_t* context = (ebpf_program_test_run_context_t*)work_item_context;
    ebpf_program_test_run_options_t* options = context->options;
    uint64_t end_time;
    // Elapsed time is computed while the program is executing, excluding time spent when yielding the CPU.
    uint64_t cumulative_time = 0;
    ebpf_result_t result;
    uint32_t return_value = 0;
    uint8_t old_irql = 0;
    uintptr_t old_thread_affinity;
    size_t batch_size = options->batch_size ? options->batch_size : 1024;
    ebpf_execution_context_state_t execution_context_state = {0};
    ebpf_epoch_state_t* epoch_state = NULL;
    bool irql_raised = false;
    bool thread_affinity_set = false;

    result = ebpf_set_current_thread_affinity((uintptr_t)1 << options->cpu, &old_thread_affinity);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }
    thread_affinity_set = true;

    old_irql = ebpf_raise_irql(context->required_irql);
    irql_raised = true;

    epoch_state = ebpf_epoch_enter();

    ebpf_get_execution_context_state(&execution_context_state);

    uint64_t start_time = ebpf_query_time_since_boot(false);
    for (size_t i = 0; i < options->repeat_count; i++) {
        if (context->canceled) {
            result = EBPF_CANCELED;
            break;
        }
        // Start a new epoch every batch_size iterations.
        if ((i % batch_size == (batch_size - 1))) {
            ebpf_epoch_exit(epoch_state);
            epoch_state = ebpf_epoch_enter();
        }
        ebpf_program_invoke(context->program, context->context, &return_value, &execution_context_state);
        if (ebpf_should_yield_processor()) {
            // Compute the elapsed time since the last yield.
            end_time = ebpf_query_time_since_boot(false);

            // Add the elapsed time to the cumulative time.
            cumulative_time += end_time - start_time;

            // Yield the CPU.
            ebpf_lower_irql(old_irql);

            // Reacquire the CPU.
            old_irql = ebpf_raise_irql(context->required_irql);

            // Reset the start time.
            start_time = ebpf_query_time_since_boot(false);
        }
    }
    end_time = ebpf_query_time_since_boot(false);

    cumulative_time += end_time - start_time;

    options->duration = cumulative_time * EBPF_NS_PER_FILETIME;
    options->duration /= options->repeat_count;
    options->return_value = return_value;

Done:
    if (epoch_state) {
        ebpf_epoch_exit(epoch_state);
    }

    if (irql_raised) {
        ebpf_lower_irql(old_irql);
    }

    if (thread_affinity_set) {
        ebpf_restore_current_thread_affinity(old_thread_affinity);
    }

    if (context->program_data && context->program_data->context_destroy != NULL && context->context != NULL) {
        context->program_data->context_destroy(
            context->context,
            options->data_out,
            &options->data_size_out,
            options->context_out,
            &options->context_size_out);
    }
    context->completion_callback(
        result, context->program, context->options, context->completion_context, context->async_context);
    ebpf_extension_dereference_provider_data(context->program->info_extension_client);
}

static void
_ebpf_program_test_run_cancel(_Inout_opt_ void* context)
{
    _Analysis_assume_(context != NULL);
    ebpf_program_test_run_context_t* test_run_context = (ebpf_program_test_run_context_t*)context;
    test_run_context->canceled = true;
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_execute_test_run(
    _In_ const ebpf_program_t* program,
    _Inout_ ebpf_program_test_run_options_t* options,
    _In_ void* async_context,
    _In_ void* completion_context,
    _In_ ebpf_program_test_run_complete_callback_t callback)
{
    EBPF_LOG_ENTRY();

    ebpf_result_t return_value = EBPF_SUCCESS;
    ebpf_program_test_run_context_t* test_run_context = NULL;
    void* context = NULL;
    ebpf_preemptible_work_item_t* work_item = NULL;
    ebpf_program_data_t* program_data = NULL;
    bool provider_data_referenced = false;

    // Prevent the provider from detaching while the program is running.
    if (!program->info_extension_client || !ebpf_extension_reference_provider_data(program->info_extension_client)) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "The extension is not loaded for program type",
            program->parameters.program_type);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    provider_data_referenced = true;

    program_data = (ebpf_program_data_t*)program->info_extension_provider_data->data;

    if (program_data->context_create == NULL || program_data->context_destroy == NULL) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Convert the input buffer to a program type specific context structure.
    return_value = program_data->context_create(
        options->data_in, options->data_size_in, options->context_in, options->context_size_in, &context);
    if (return_value != 0) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    test_run_context = (ebpf_program_test_run_context_t*)ebpf_allocate_with_tag(
        sizeof(ebpf_program_test_run_context_t), EBPF_POOL_TAG_PROGRAM);
    if (test_run_context == NULL) {
        return_value = EBPF_NO_MEMORY;
        goto Exit;
    }

    test_run_context->program = program;
    test_run_context->program_data = program_data;
    test_run_context->required_irql = program_data->required_irql;
    test_run_context->context = context;
    test_run_context->options = options;
    test_run_context->async_context = async_context;
    test_run_context->completion_context = completion_context;
    test_run_context->completion_callback = callback;

    // Queue the work item so that it can be executed on the target CPU and at the target dispatch level.
    // The work item will signal the completion event when it is done.
    return_value = ebpf_allocate_preemptible_work_item(&work_item, _ebpf_program_test_run_work_item, test_run_context);
    if (return_value != EBPF_SUCCESS) {
        goto Exit;
    }

    ebpf_assert_success(ebpf_async_set_cancel_callback(async_context, test_run_context, _ebpf_program_test_run_cancel));

    // ebpf_queue_preemptible_work_item() will free both the work item and the context when it is done.
    ebpf_queue_preemptible_work_item(work_item);

    // This thread no longer owns the test run context.
    test_run_context = NULL;
    // This thread no longer owns the reference to the provider data.
    provider_data_referenced = false;
    // This thread no longer owns the BPF context.
    context = NULL;
    return_value = EBPF_PENDING;

Exit:
    if (program_data && program_data->context_destroy != NULL && context != NULL) {
        program_data->context_destroy(
            context, options->data_out, &options->data_size_out, options->context_out, &options->context_size_out);
    }
    ebpf_free(test_run_context);

    if (provider_data_referenced) {
        ebpf_extension_dereference_provider_data(program->info_extension_client);
    }
    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_register_for_helper_changes(
    _Inout_ ebpf_program_t* program,
    _In_ ebpf_helper_function_addresses_changed_callback_t callback,
    _In_opt_ void* context)
{
    if (program->helper_function_addresses_changed_callback != NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    program->helper_function_addresses_changed_callback = callback;
    program->helper_function_addresses_changed_context = context;
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_get_program_file_name(_In_ const ebpf_program_t* program, _Out_ ebpf_utf8_string_t* file_name)
{
    ebpf_lock_state_t state = ebpf_lock_lock((ebpf_lock_t*)&program->lock);
    ebpf_result_t return_value = ebpf_duplicate_utf8_string(file_name, &program->parameters.file_name);
    ebpf_lock_unlock((ebpf_lock_t*)&program->lock, state);
    return return_value;
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_get_program_section_name(_In_ const ebpf_program_t* program, _Out_ ebpf_utf8_string_t* section_name)
{
    ebpf_lock_state_t state = ebpf_lock_lock((ebpf_lock_t*)&program->lock);
    ebpf_result_t return_value = ebpf_duplicate_utf8_string(section_name, &program->parameters.section_name);
    ebpf_lock_unlock((ebpf_lock_t*)&program->lock, state);
    return return_value;
}

ebpf_code_type_t
ebpf_program_get_code_type(_In_ const ebpf_program_t* program)
{
    ebpf_lock_state_t state = ebpf_lock_lock((ebpf_lock_t*)&program->lock);
    ebpf_code_type_t code_type = program->parameters.code_type;
    ebpf_lock_unlock((ebpf_lock_t*)&program->lock, state);
    return code_type;
}