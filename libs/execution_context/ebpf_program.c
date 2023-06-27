// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_PROGRAM

#include "bpf_helpers.h"
#include "ebpf_async.h"
#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_native.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_program_types.h"
#include "ebpf_state.h"
#include "ebpf_tracelog.h"
#include "ubpf.h"

#include <stdlib.h>

static size_t _ebpf_program_state_index = MAXUINT64;
#define EBPF_MAX_HASH_SIZE 128

typedef struct _ebpf_program
{
    ebpf_core_object_t object;

    _Guarded_by_(lock) ebpf_program_parameters_t parameters;

    // determinant is parameters.code_type
    union
    {
        // EBPF_CODE_JIT
        struct
        {
            ebpf_memory_descriptor_t* code_memory_descriptor;
            const uint8_t* code_pointer;
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

    // NMR client handles for program information providers.
    NPI_CLIENT_CHARACTERISTICS general_program_information_client_characteristics;
    HANDLE general_program_information_nmr_handle;
    NPI_CLIENT_CHARACTERISTICS type_specific_program_information_client_characteristics;
    HANDLE type_specific_program_information_nmr_handle;
    NPI_MODULEID module_id;

    EX_RUNDOWN_REF program_information_rundown_reference;

    const ebpf_extension_data_t* general_helper_provider_data;
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

static struct
{
    int reserved;
} _ebpf_program_information_client_dispatch_table;

static NPI_CLIENT_ATTACH_PROVIDER_FN _ebpf_program_general_program_information_attach_provider;
static NPI_CLIENT_DETACH_PROVIDER_FN _ebpf_program_general_program_information_detach_provider;

static const NPI_CLIENT_CHARACTERISTICS _ebpf_program_general_program_information_client_characteristics = {
    0,
    sizeof(_ebpf_program_general_program_information_client_characteristics),
    _ebpf_program_general_program_information_attach_provider,
    _ebpf_program_general_program_information_detach_provider,
    NULL,
    {
        EBPF_PROGRAM_INFORMATION_PROVIDER_DATA_VERSION,
        sizeof(NPI_REGISTRATION_INSTANCE),
        &EBPF_PROGRAM_INFO_EXTENSION_IID,
        NULL,
        0,
        NULL,
    },
};

static NPI_CLIENT_ATTACH_PROVIDER_FN _ebpf_program_type_specific_program_information_attach_provider;
static NPI_CLIENT_DETACH_PROVIDER_FN _ebpf_program_type_specific_program_information_detach_provider;

static const NPI_CLIENT_CHARACTERISTICS _ebpf_program_type_specific_program_information_client_characteristics = {
    0,
    sizeof(_ebpf_program_type_specific_program_information_client_characteristics),
    _ebpf_program_type_specific_program_information_attach_provider,
    _ebpf_program_type_specific_program_information_detach_provider,
    NULL,
    {
        EBPF_PROGRAM_INFORMATION_PROVIDER_DATA_VERSION,
        sizeof(NPI_REGISTRATION_INSTANCE),
        &EBPF_PROGRAM_INFO_EXTENSION_IID,
        NULL,
        0,
        NULL,
    },
};

_Requires_lock_held_(program->lock) static ebpf_result_t _ebpf_program_update_helpers(_Inout_ ebpf_program_t* program);

static ebpf_result_t
_ebpf_program_update_interpret_helpers(
    size_t address_count, _In_reads_(address_count) const uintptr_t* addresses, _Inout_ void* context);

static ebpf_result_t
_ebpf_program_update_jit_helpers(
    size_t address_count, _In_reads_(address_count) const uintptr_t* addresses, _Inout_ void* context);

_Requires_lock_held_(program->lock) static ebpf_result_t _ebpf_program_get_helper_function_address(
    _In_ const ebpf_program_t* program, const uint32_t helper_function_id, _Out_ uint64_t* address);

_Must_inspect_result_ ebpf_result_t
ebpf_program_initiate()
{
    return ebpf_state_allocate_index(&_ebpf_program_state_index);
}

void
ebpf_program_terminate()
{}

_Requires_lock_not_held_(program->lock) static void _ebpf_program_detach_links(_Inout_ ebpf_program_t* program)
{
    EBPF_LOG_ENTRY();
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&program->lock);
    while (!ebpf_list_is_empty(&program->links)) {
        ebpf_list_entry_t* entry = program->links.Flink;
        ebpf_core_object_t* object = CONTAINING_RECORD(entry, ebpf_core_object_t, object_list_entry);
        // Acquire a reference on the object to prevent it from going away.
        EBPF_OBJECT_ACQUIRE_REFERENCE(object);

        // Release the lock before calling detach.
        ebpf_lock_unlock(&program->lock, state);
        ebpf_link_detach_program((ebpf_link_t*)object);

        EBPF_OBJECT_RELEASE_REFERENCE(object);
        state = ebpf_lock_lock(&program->lock);
    }
    ebpf_lock_unlock(&program->lock, state);

    EBPF_RETURN_VOID();
}

static ebpf_result_t
_ebpf_program_compute_program_information_hash(
    _In_ const ebpf_program_data_t* general_program_information_data,
    _In_ const ebpf_program_data_t* type_specific_program_information_data,
    _In_ const ebpf_utf8_string_t* hash_algorithm,
    _Outptr_ uint8_t** hash,
    _Out_ size_t* hash_length);

static NTSTATUS
_ebpf_program_general_program_information_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    const ebpf_extension_data_t* provider_data =
        (const ebpf_extension_data_t*)provider_registration_instance->NpiSpecificCharacteristics;
    ebpf_program_t* program = (ebpf_program_t*)client_context;
    NTSTATUS status;

    void* provider_binding_context;
    void* provider_dispatch;

    bool lock_held = false;

    ebpf_lock_state_t state = ebpf_lock_lock(&program->lock);
    lock_held = true;

    // Verify that that the provider is using the same version of the extension as the client.
    if (provider_data->version > EBPF_PROGRAM_INFORMATION_PROVIDER_DATA_VERSION ||
        provider_data->size < sizeof(ebpf_program_data_t)) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Global program information provider version mismatch.");
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    if (provider_registration_instance->ModuleId->Type != MIT_GUID) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Global program information provider module ID type mismatch.");
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    if (memcmp(
            &provider_registration_instance->ModuleId->Guid,
            &ebpf_general_helper_function_module_id.Guid,
            sizeof(GUID)) != 0) {
        status = STATUS_NOINTERFACE;
        // This is expected as the attach callback will be called for each provider of NPI
        // EBPF_PROGRAM_INFO_EXTENSION_IID.
        goto Done;
    }

    if (program->general_helper_provider_data != NULL) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Global program information provider already attached.");
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    program->general_helper_provider_data = provider_data;
    const ebpf_program_data_t* program_data = (const ebpf_program_data_t*)program->general_helper_provider_data->data;

    program->global_helper_function_count =
        program_data->program_type_specific_helper_function_addresses->helper_function_count;

    ebpf_lock_unlock(&program->lock, state);
    lock_held = false;

    status = NmrClientAttachProvider(
        nmr_binding_handle,
        program,
        &_ebpf_program_information_client_dispatch_table,
        &provider_binding_context,
        &provider_dispatch);

    state = ebpf_lock_lock(&program->lock);
    lock_held = true;

    if (!NT_SUCCESS(status)) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "NmrClientAttachProvider failed for global program information provider.",
            status);
        program->general_helper_provider_data = NULL;
        goto Done;
    }

Done:
    if (lock_held) {
        ebpf_lock_unlock(&program->lock, state);
    }

    return status;
}

static NTSTATUS
_ebpf_program_general_program_information_detach_provider(void* client_binding_context)
{
    ebpf_program_t* program = (ebpf_program_t*)client_binding_context;
    ebpf_lock_state_t state = ebpf_lock_lock(&program->lock);
    program->general_helper_provider_data = NULL;
    ebpf_lock_unlock(&program->lock, state);
    return STATUS_SUCCESS;
}

static NTSTATUS
_ebpf_program_type_specific_program_information_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    const ebpf_extension_data_t* provider_data =
        (const ebpf_extension_data_t*)provider_registration_instance->NpiSpecificCharacteristics;
    ebpf_program_t* program = (ebpf_program_t*)client_context;
    const ebpf_program_data_t* type_specific_program_information_data;
    const ebpf_program_data_t* general_program_information_data;
    ebpf_utf8_string_t hash_algorithm = {0};
    NTSTATUS status;
    uint8_t* hash = NULL;
    size_t hash_length = 0;

    void* provider_binding_context;
    void* provider_dispatch;

    bool lock_held = false;

    ebpf_lock_state_t state = ebpf_lock_lock(&program->lock);
    lock_held = true;

    if (ebpf_duplicate_utf8_string(&hash_algorithm, &program->parameters.program_info_hash_type) != EBPF_SUCCESS) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    if (!program->general_helper_provider_data) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Type specific program information provider attached before global program information provider.");
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    general_program_information_data = (ebpf_program_data_t*)program->general_helper_provider_data->data;

    ebpf_lock_unlock(&program->lock, state);
    lock_held = false;

    // Verify that that the provider is using the same version of the extension as the client.
    if (provider_data->version > EBPF_PROGRAM_INFORMATION_PROVIDER_DATA_VERSION ||
        provider_data->size < sizeof(ebpf_program_data_t)) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Program information provider version mismatch.",
            &program->parameters.program_type);
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    if (provider_registration_instance->ModuleId->Type != MIT_GUID) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Program information provider module ID type mismatch.",
            &program->parameters.program_type);
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    if (memcmp(&provider_registration_instance->ModuleId->Guid, &program->parameters.program_type, sizeof(GUID)) != 0) {
        // This is expected as the attach callback will be called for each provider of NPI
        // EBPF_PROGRAM_INFO_EXTENSION_IID.
        status = STATUS_NOINTERFACE;
        goto Done;
    }

    type_specific_program_information_data = (ebpf_program_data_t*)provider_data->data;

    // Compute the hash of the program information. This requires passive IRQL and must be done outside the lock.
    if (_ebpf_program_compute_program_information_hash(
            general_program_information_data,
            type_specific_program_information_data,
            &hash_algorithm,
            &hash,
            &hash_length) != EBPF_SUCCESS) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    state = ebpf_lock_lock(&program->lock);
    lock_held = true;

    if (program->info_extension_provider_data != NULL) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Program information provider already attached.",
            &program->parameters.program_type);
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }
    program->info_extension_provider_data = provider_data;

    // If there is no stored hash, then this is the first time the extension is being attached.
    if (program->parameters.program_info_hash_length == 0) {
        program->parameters.program_info_hash_length = hash_length;
        program->parameters.program_info_hash = hash;
        hash = NULL;
    } else {
        // Verify that the hash matches the stored hash.
        if (program->parameters.program_info_hash_length != hash_length ||
            memcmp(program->parameters.program_info_hash, hash, hash_length) != 0) {
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_PROGRAM,
                "Program information provider hash mismatch.",
                &program->parameters.program_type);
            status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
    }

    const ebpf_program_data_t* program_data = (const ebpf_program_data_t*)provider_data->data;
    if (program_data == NULL) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "An extension cannot have empty program_data",
            &program->parameters.program_type);
        // An extension cannot have empty program_data.
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    if (program_data->required_irql > HIGH_LEVEL) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "An extension cannot have required_irql higher than HIGH_LEVEL",
            &program->parameters.program_type);
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    if ((program_data->program_type_specific_helper_function_addresses) &&
        program_data->program_type_specific_helper_function_addresses->helper_function_count !=
            program_data->program_info->count_of_program_type_specific_helpers) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "An extension cannot have a mismatch between the number of helper functions and the number of helper "
            "function addresses",
            &program->parameters.program_type);
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    if ((program_data->global_helper_function_addresses) &&
        (program_data->global_helper_function_addresses->helper_function_count !=
         program_data->program_info->count_of_global_helpers)) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "An extension cannot have a mismatch between the number of helper functions and the number of helper "
            "function addresses",
            &program->parameters.program_type);
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    // This should be done after the call to NmrClientAttachProvider, but _ebpf_program_update_helpers requires
    // the program information to be set.

    // Unblock calls to use the program information.
    program->info_extension_provider_data = provider_data;
    ExInitializeRundownProtection(&program->program_information_rundown_reference);

    program->program_type_specific_helper_function_count =
        program_data->program_info->count_of_program_type_specific_helpers;

    if (_ebpf_program_update_helpers(program) != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_PROGRAM, "Failed to update helpers for program");
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    program->bpf_prog_type = program_data->program_info->program_type_descriptor.bpf_prog_type;

    ebpf_lock_unlock(&program->lock, state);
    lock_held = false;

    status = NmrClientAttachProvider(
        nmr_binding_handle,
        program,
        &_ebpf_program_information_client_dispatch_table,
        &provider_binding_context,
        &provider_dispatch);

    if (!NT_SUCCESS(status)) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "NmrClientAttachProvider failed for program information provider.",
            status);
        ExWaitForRundownProtectionRelease(&program->program_information_rundown_reference);
        state = ebpf_lock_lock(&program->lock);
        lock_held = true;

        program->general_helper_provider_data = NULL;
        ebpf_lock_unlock(&program->lock, state);
        lock_held = false;
        goto Done;
    }

Done:
    ebpf_free(hash);
    ebpf_free(hash_algorithm.value);

    if (lock_held) {
        ebpf_lock_unlock(&program->lock, state);
    }

    return status;
}

static NTSTATUS
_ebpf_program_type_specific_program_information_detach_provider(void* client_binding_context)
{
    ebpf_program_t* program = (ebpf_program_t*)client_binding_context;

    ExWaitForRundownProtectionRelease(&program->program_information_rundown_reference);

    ebpf_lock_state_t state = ebpf_lock_lock(&program->lock);
    program->info_extension_provider_data = NULL;
    ebpf_lock_unlock(&program->lock, state);
    return STATUS_SUCCESS;
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
        EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)program->maps[index]);
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
 * _ebpf_program_free. This function will block until the provider has finished
 * detaching.
 *
 * @param[in] context Pointer to the ebpf_program_t passed as context in the
 * work-item.
 */
_IRQL_requires_max_(PASSIVE_LEVEL) static void _ebpf_program_epoch_free(_In_opt_ _Post_invalid_ void* context)
{
    if (!context) {
        return;
    }

    EBPF_LOG_ENTRY();
    ebpf_program_t* program = (ebpf_program_t*)context;

    if (program->type_specific_program_information_nmr_handle) {
        NTSTATUS status = NmrDeregisterClient(program->type_specific_program_information_nmr_handle);
        if (status == STATUS_PENDING) {
            NmrWaitForClientDeregisterComplete(program->type_specific_program_information_nmr_handle);
        } else {
            ebpf_assert(NT_SUCCESS(status));
        }
    }

    if (program->general_program_information_nmr_handle) {
        NTSTATUS status = NmrDeregisterClient(program->general_program_information_nmr_handle);
        if (status == STATUS_PENDING) {
            NmrWaitForClientDeregisterComplete(program->general_program_information_nmr_handle);
        } else {
            ebpf_assert(NT_SUCCESS(status));
        }
    }

    ebpf_lock_destroy(&program->lock);

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
    ebpf_free(program->parameters.program_info_hash_type.value);

    ebpf_free(program->maps);

    ebpf_free_trampoline_table(program->trampoline_table);

    ebpf_free(program->helper_function_ids);

    ebpf_epoch_cancel_work_item(program->cleanup_work_item);
    ebpf_free(program);
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_create(_In_ const ebpf_program_parameters_t* program_parameters, _Outptr_ ebpf_program_t** program)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_program_t* local_program = NULL;
    ebpf_utf8_string_t local_program_name = {NULL, 0};
    ebpf_utf8_string_t local_section_name = {NULL, 0};
    ebpf_utf8_string_t local_file_name = {NULL, 0};
    ebpf_utf8_string_t local_hash_type_name = {NULL, 0};
    uint8_t* local_program_info_hash = NULL;

    if (IsEqualGUID(&program_parameters->program_type, &EBPF_PROGRAM_TYPE_UNSPECIFIED)) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Program type must be specified.",
            &program_parameters->program_type);
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    local_program = (ebpf_program_t*)ebpf_allocate_with_tag(sizeof(ebpf_program_t), EBPF_POOL_TAG_PROGRAM);
    if (!local_program) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(local_program, 0, sizeof(ebpf_program_t));

    local_program->module_id.Type = MIT_GUID;
    local_program->module_id.Length = sizeof(local_program->module_id);
    retval = ebpf_guid_create(&local_program->module_id.Guid);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    local_program->cleanup_work_item = ebpf_epoch_allocate_work_item(local_program, _ebpf_program_epoch_free);
    if (!local_program->cleanup_work_item) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    ebpf_list_initialize(&local_program->links);
    ebpf_lock_create(&local_program->lock);

    local_program->bpf_prog_type = BPF_PROG_TYPE_UNSPEC;

    if (program_parameters->program_name.length >= BPF_OBJ_NAME_LEN) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Program name must be less than BPF_OBJ_NAME_LEN",
            program_parameters->program_name.length);
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    retval = ebpf_duplicate_utf8_string(&local_program_name, &program_parameters->program_name);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_duplicate_utf8_string(&local_section_name, &program_parameters->section_name);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_duplicate_utf8_string(&local_file_name, &program_parameters->file_name);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    if (program_parameters->program_info_hash_length > 0) {
        local_program_info_hash =
            ebpf_allocate_with_tag(program_parameters->program_info_hash_length, EBPF_POOL_TAG_PROGRAM);
        if (!local_program_info_hash) {
            retval = EBPF_NO_MEMORY;
            goto Done;
        }
        memcpy(
            local_program_info_hash,
            program_parameters->program_info_hash,
            program_parameters->program_info_hash_length);
    }

    // If the hash type is not specified, use the default hash type.
    if (program_parameters->program_info_hash_type.length == 0) {
        ebpf_utf8_string_t hash_algorithm = EBPF_UTF8_STRING_FROM_CONST_STRING(EBPF_HASH_ALGORITHM);
        retval = ebpf_duplicate_utf8_string(&local_hash_type_name, &hash_algorithm);
    } else {
        retval = ebpf_duplicate_utf8_string(&local_hash_type_name, &program_parameters->program_info_hash_type);
    }

    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    local_program->parameters = *program_parameters;

    local_program->parameters.program_name = local_program_name;
    local_program_name.value = NULL;
    local_program->parameters.section_name = local_section_name;
    local_section_name.value = NULL;
    local_program->parameters.file_name = local_file_name;
    local_file_name.value = NULL;

    local_program->parameters.code_type = EBPF_CODE_NONE;
    local_program->parameters.program_info_hash = local_program_info_hash;
    local_program_info_hash = NULL;
    local_program->parameters.program_info_hash_type = local_hash_type_name;
    local_hash_type_name.value = NULL;

    local_program->general_program_information_client_characteristics =
        _ebpf_program_general_program_information_client_characteristics;
    local_program->general_program_information_client_characteristics.ClientRegistrationInstance.ModuleId =
        &local_program->module_id;
    local_program->type_specific_program_information_client_characteristics =
        _ebpf_program_type_specific_program_information_client_characteristics;
    local_program->type_specific_program_information_client_characteristics.ClientRegistrationInstance.ModuleId =
        &local_program->module_id;

    // Mark the program_information_rundown_reference as rundown to prevent programs
    // from using it.
    ExInitializeRundownProtection(&local_program->program_information_rundown_reference);
    ExWaitForRundownProtectionRelease(&local_program->program_information_rundown_reference);

    NTSTATUS status = NmrRegisterClient(
        &local_program->general_program_information_client_characteristics,
        local_program,
        &local_program->general_program_information_nmr_handle);

    if (status != STATUS_SUCCESS) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    status = NmrRegisterClient(
        &local_program->type_specific_program_information_client_characteristics,
        local_program,
        &local_program->type_specific_program_information_nmr_handle);

    if (status != STATUS_SUCCESS) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    if (local_program->general_helper_provider_data == NULL || local_program->info_extension_provider_data == NULL) {
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "Program type and Attach type:",
            &program_parameters->program_type,
            &program_parameters->expected_attach_type);
        retval = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    // Note: This is performed after initializing the program as it inserts the program into the global list.
    // From this point on, the program can be found by other threads.
    retval = EBPF_OBJECT_INITIALIZE(
        &local_program->object, EBPF_OBJECT_PROGRAM, _ebpf_program_free, _ebpf_program_get_program_type);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    *program = local_program;
    local_program = NULL;
    retval = EBPF_SUCCESS;

Done:
    ebpf_free(local_program_info_hash);
    ebpf_free(local_program_name.value);
    ebpf_free(local_section_name.value);
    ebpf_free(local_file_name.value);

    _ebpf_program_epoch_free(local_program);

    EBPF_RETURN_RESULT(retval);
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

    EBPF_OBJECT_ACQUIRE_REFERENCE((ebpf_core_object_t*)map);
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
        EBPF_OBJECT_ACQUIRE_REFERENCE((ebpf_core_object_t*)program->maps[index]);
    }
    ebpf_lock_unlock(&program->lock, state);

Done:
    ebpf_free(program_maps);

    EBPF_RETURN_RESULT(result);
}

_Requires_lock_held_(program->lock) static ebpf_result_t _ebpf_program_load_machine_code(
    _Inout_ ebpf_program_t* program,
    _In_opt_ const void* code_context,
    _In_reads_(machine_code_size) const uint8_t* machine_code,
    size_t machine_code_size)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    const uint8_t* local_machine_code = NULL;
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

        memcpy((void*)local_machine_code, machine_code, machine_code_size);

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

_Requires_lock_held_(program->lock) static ebpf_result_t _ebpf_program_update_helpers(_Inout_ ebpf_program_t* program)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uintptr_t* helper_function_addresses = NULL;
    if (program->parameters.code_type == EBPF_CODE_NATIVE) {

        // We _can_ have instances of ebpf programs that do not need to call any helper functions.
        // Such programs are valid and the 'program->helper_function_count' member for such programs will be 0 (Zero).
        if (program->helper_function_count) {
            helper_function_addresses =
                ebpf_allocate_with_tag(program->helper_function_count * sizeof(uintptr_t), EBPF_POOL_TAG_PROGRAM);
            if (helper_function_addresses == NULL) {
                result = EBPF_NO_MEMORY;
                goto Done;
            }
        }

        for (uint32_t index = 0; index < program->helper_function_count; index++) {
            result = _ebpf_program_get_helper_function_address(
                program, program->helper_function_ids[index], &helper_function_addresses[index]);
            if (result != EBPF_SUCCESS) {
                goto Done;
            }
        }
    }

    if (program->helper_function_addresses_changed_callback != NULL) {
        result = program->helper_function_addresses_changed_callback(
            program->helper_function_count,
            helper_function_addresses,
            program->helper_function_addresses_changed_context);
    }
Done:
    ebpf_free(helper_function_addresses);
    return result;
}

static ebpf_result_t
_ebpf_program_update_interpret_helpers(
    size_t address_count, _In_reads_(address_count) const uintptr_t* addresses, _Inout_ void* context)
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(address_count);
    UNREFERENCED_PARAMETER(addresses);

    ebpf_program_t* program = (ebpf_program_t*)context;
    _Analysis_assume_lock_held_(program->lock);
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
_ebpf_program_update_jit_helpers(
    size_t address_count, _In_reads_(address_count) const uintptr_t* addresses, _Inout_ void* context)
{
    ebpf_result_t return_value;
    UNREFERENCED_PARAMETER(address_count);
    UNREFERENCED_PARAMETER(addresses);
    ebpf_program_t* program = (ebpf_program_t*)context;
    ebpf_program_data_t* program_data = NULL;
    const ebpf_helper_function_addresses_t* helper_function_addresses = NULL;
    const ebpf_helper_function_addresses_t* global_helper_function_addresses = NULL;

    size_t total_helper_count = 0;
    ebpf_helper_function_addresses_t* total_helper_function_addresses = NULL;
    uint32_t* total_helper_function_ids = NULL;
    bool provider_data_referenced = false;

    if (ebpf_program_reference_providers(program) != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "The extension is not loaded for program type",
            &program->parameters.program_type);
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
                &program->parameters.program_type);
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
                    &program->parameters.program_type);
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
                    &program->parameters.program_type);
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
        ebpf_program_dereference_providers(program);
    }

    return return_value;
}

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
_Requires_lock_held_(program->lock) static ebpf_result_t _ebpf_program_load_byte_code(
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
    program->helper_function_addresses_changed_context = program;

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
    ebpf_lock_state_t state = ebpf_lock_lock(&program->lock);
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

    ebpf_lock_unlock(&program->lock, state);
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

    if (state->count == (MAX_TAIL_CALL_CNT - 1)) {
        EBPF_OBJECT_RELEASE_REFERENCE(&((ebpf_program_t*)next_program)->object);
        return EBPF_NO_MORE_TAIL_CALLS;
    }

    state->next_program = next_program;

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_reference_providers(_Inout_ ebpf_program_t* program)
{
    if (program->info_extension_provider_data == NULL) {
        return EBPF_EXTENSION_FAILED_TO_LOAD;
    }
    if (!ExAcquireRundownProtection(&program->program_information_rundown_reference)) {
        return EBPF_EXTENSION_FAILED_TO_LOAD;
    }
    return EBPF_SUCCESS;
}

void
ebpf_program_dereference_providers(_Inout_ ebpf_program_t* program)
{
    ExReleaseRundownProtection(&program->program_information_rundown_reference);
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
            EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)current_program);
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

_Requires_lock_held_(program->lock) static ebpf_result_t _ebpf_program_get_helper_function_address(
    _In_ const ebpf_program_t* program, const uint32_t helper_function_id, _Out_ uint64_t* address)
{
    ebpf_result_t return_value;
    uint64_t* function_address = NULL;
    ebpf_program_data_t* program_data = NULL;
    ebpf_program_data_t* general_program_data = NULL;

    EBPF_LOG_ENTRY();

    bool provider_data_referenced = false;
    bool use_trampoline = false;
    bool found = false;

    if (ebpf_program_reference_providers((ebpf_program_t*)program) != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "The extension is not loaded for program type",
            &program->parameters.program_type);
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
        ebpf_program_dereference_providers((ebpf_program_t*)program);
    }
    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_get_helper_function_addresses(
    _In_ const ebpf_program_t* program, size_t addresses_count, _Out_writes_(addresses_count) uint64_t* addresses)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state = ebpf_lock_lock((ebpf_lock_t*)&program->lock);

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
    ebpf_lock_unlock((ebpf_lock_t*)&program->lock, state);
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

    if (ebpf_program_reference_providers((ebpf_program_t*)program) != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "The extension is not loaded for program type",
            &program->parameters.program_type);
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
            &program->parameters.program_type);
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
        ebpf_program_dereference_providers((ebpf_program_t*)program);
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
    EBPF_OBJECT_ACQUIRE_REFERENCE((ebpf_core_object_t*)link);

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
    EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)link);
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
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    ebpf_program_t* program = NULL;

    retval = ebpf_program_create(parameters, &program);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    retval = ebpf_handle_create(program_handle, (ebpf_base_object_t*)program);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)program);
    EBPF_RETURN_RESULT(retval);
}

typedef struct _ebpf_helper_id_to_index
{
    uint32_t helper_id;
    const ebpf_helper_function_prototype_t* helper_function_prototype;
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
_ebpf_program_compute_program_information_hash(
    _In_ const ebpf_program_data_t* general_program_information_data,
    _In_ const ebpf_program_data_t* type_specific_program_information_data,
    _In_ const ebpf_utf8_string_t* hash_algorithm,
    _Outptr_ uint8_t** hash,
    _Out_ size_t* hash_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_cryptographic_hash_t* cryptographic_hash = NULL;
    ebpf_helper_id_to_index_t* helper_id_to_index = NULL;
    const ebpf_program_info_t* type_specific_program_info = type_specific_program_information_data->program_info;
    const ebpf_program_info_t* general_program_info = general_program_information_data->program_info;
    uint32_t helper_function_count = type_specific_program_info->count_of_program_type_specific_helpers +
                                     general_program_info->count_of_program_type_specific_helpers;
    uint32_t helper_function_index = 0;

    helper_id_to_index = (ebpf_helper_id_to_index_t*)ebpf_allocate_with_tag(
        helper_function_count * sizeof(ebpf_helper_id_to_index_t), EBPF_POOL_TAG_PROGRAM);
    if (helper_id_to_index == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Copy global helpers to helper_id_to_index.
    for (uint32_t index = 0; index < general_program_info->count_of_program_type_specific_helpers; index++) {
        helper_id_to_index[helper_function_index].helper_id =
            general_program_info->program_type_specific_helper_prototype[index].helper_id;
        helper_id_to_index[helper_function_index].helper_function_prototype =
            &general_program_info->program_type_specific_helper_prototype[index];
        helper_function_index++;
    }

    // Copy program type specific helpers to helper_id_to_index.
    for (uint32_t index = 0; index < type_specific_program_info->count_of_program_type_specific_helpers; index++) {
        helper_id_to_index[helper_function_index].helper_id =
            type_specific_program_info->program_type_specific_helper_prototype[index].helper_id;
        helper_id_to_index[helper_function_index].helper_function_prototype =
            &type_specific_program_info->program_type_specific_helper_prototype[index];
        helper_function_index++;
    }

    // Sort helper_id_to_index by helper_id.
    qsort(
        helper_id_to_index, helper_function_count, sizeof(ebpf_helper_id_to_index_t), _ebpf_helper_id_to_index_compare);

    result = ebpf_cryptographic_hash_create(hash_algorithm, &cryptographic_hash);

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

    result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_STR(
        cryptographic_hash, type_specific_program_info->program_type_descriptor.name);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(
        cryptographic_hash, *type_specific_program_info->program_type_descriptor.context_descriptor);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(
        cryptographic_hash, type_specific_program_info->program_type_descriptor.program_type);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(
        cryptographic_hash, type_specific_program_info->program_type_descriptor.bpf_prog_type);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(
        cryptographic_hash, type_specific_program_info->program_type_descriptor.is_privileged);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(cryptographic_hash, helper_function_count);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    for (uint32_t index = 0; index < helper_function_count; index++) {
        const ebpf_helper_function_prototype_t* helper_function_prototype =
            helper_id_to_index[index].helper_function_prototype;
        result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(cryptographic_hash, helper_function_prototype->helper_id);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_STR(cryptographic_hash, helper_function_prototype->name);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(cryptographic_hash, helper_function_prototype->return_type);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        for (uint32_t j = 0; j < EBPF_COUNT_OF(helper_function_prototype->arguments); j++) {
            result = EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(cryptographic_hash, helper_function_prototype->arguments[j]);
            if (result != EBPF_SUCCESS) {
                goto Exit;
            }
        }
    }
    *hash_length = 0;
    result = ebpf_cryptographic_hash_get_hash_length(cryptographic_hash, hash_length);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    *hash = (uint8_t*)ebpf_allocate(*hash_length);
    if (*hash == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    result = ebpf_cryptographic_hash_get_hash(cryptographic_hash, *hash, *hash_length, hash_length);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = EBPF_SUCCESS;

Exit:
    ebpf_free(helper_id_to_index);
    ebpf_cryptographic_hash_destroy(cryptographic_hash);

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
    ebpf_program_dereference_providers((ebpf_program_t*)context->program);
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
    if (ebpf_program_reference_providers((ebpf_program_t*)program) != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_PROGRAM,
            "The extension is not loaded for program type",
            &program->parameters.program_type);
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
        ebpf_program_dereference_providers((ebpf_program_t*)program);
    }
    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_program_register_for_helper_changes(
    _Inout_ ebpf_program_t* program,
    _In_opt_ ebpf_helper_function_addresses_changed_callback_t callback,
    _In_opt_ void* context)
{
    ebpf_lock_state_t state = ebpf_lock_lock((ebpf_lock_t*)&program->lock);

    program->helper_function_addresses_changed_callback = callback;
    program->helper_function_addresses_changed_context = context;
    ebpf_lock_unlock((ebpf_lock_t*)&program->lock, state);
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