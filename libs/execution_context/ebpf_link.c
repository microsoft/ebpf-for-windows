// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_LINK

#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_object.h"
#include "ebpf_platform.h"
#include "ebpf_program.h"
#include "ebpf_state.h"
#include "ebpf_tracelog.h"

/**
 * @brief State of the link between program and provider.
 * Legal state transitions are:
 * 1. EBPF_LINK_STATE_INITIAL -> EBPF_LINK_STATE_ATTACHING - Program is being attached to a provider.
 * 2. EBPF_LINK_STATE_ATTACHING -> EBPF_LINK_STATE_ATTACHED - NmrRegisterClient returns success.
 * 3. EBPF_LINK_STATE_ATTACHING -> EBPF_LINK_STATE_DETACHING - Provider failed to attach.
 * 4. EBPF_LINK_STATE_ATTACHED -> EBPF_LINK_STATE_DETACHING - Program is being detached from a provider.
 * 5. EBPF_LINK_STATE_DETACHING -> EBPF_LINK_STATE_DETACHED - NmrDeregisterClient returns success.
 */
typedef enum _ebpf_link_state
{
    EBPF_LINK_STATE_INITIAL,   ///< Program is not attached to any provider.
    EBPF_LINK_STATE_ATTACHING, ///< Program is being attached to a provider.
    EBPF_LINK_STATE_ATTACHED,  ///< Program is attached to a provider.
    EBPF_LINK_STATE_DETACHING, ///< Program is being detached from a provider.
    EBPF_LINK_STATE_DETACHED,  ///< Program is detached from a provider.
} ebpf_link_state_t;

typedef struct _ebpf_link
{
    ebpf_core_object_t object;
    ebpf_lock_t lock;
    _Guarded_by_(lock) NPI_MODULEID module_id;
    _Guarded_by_(lock) ebpf_program_t* program;
    _Guarded_by_(lock) ebpf_attach_type_t attach_type;
    _Guarded_by_(lock) bpf_attach_type_t bpf_attach_type;
    _Guarded_by_(lock) enum bpf_link_type link_type;
    _Guarded_by_(lock) ebpf_program_type_t program_type;
    _Guarded_by_(lock) ebpf_extension_data_t client_data;
    _Guarded_by_(lock) NPI_CLIENT_CHARACTERISTICS client_characteristics;
    _Guarded_by_(lock) HANDLE nmr_client_handle;
    _Guarded_by_(lock) bool provider_attached;
    _Guarded_by_(lock) ebpf_link_state_t state;
} ebpf_link_t;

static NPI_CLIENT_ATTACH_PROVIDER_FN _ebpf_link_client_attach_provider;
static NPI_CLIENT_DETACH_PROVIDER_FN _ebpf_link_client_detach_provider;

static const NPI_CLIENT_CHARACTERISTICS _ebpf_link_client_characteristics = {
    0,
    sizeof(_ebpf_link_client_characteristics),
    _ebpf_link_client_attach_provider,
    _ebpf_link_client_detach_provider,
    NULL,
    {
        EBPF_ATTACH_CLIENT_DATA_CURRENT_VERSION,
        sizeof(NPI_REGISTRATION_INSTANCE),
        &EBPF_HOOK_EXTENSION_IID,
        NULL,
        0,
        NULL,
    },
};

_Requires_lock_held_(link->lock) static void _ebpf_link_set_state(
    _Inout_ ebpf_link_t* link, ebpf_link_state_t new_state);

static ebpf_result_t
_ebpf_link_instance_invoke(
    _In_ const void* extension_client_binding_context, _Inout_ void* program_context, _Out_ uint32_t* result);

static ebpf_result_t
_ebpf_link_instance_invoke_batch_begin(
    _In_ const void* extension_client_binding_context, size_t state_size, _Out_writes_(state_size) void* state);

static ebpf_result_t
_ebpf_link_instance_invoke_batch(
    _In_ const void* extension_client_binding_context,
    _Inout_ void* program_context,
    _Out_ uint32_t* result,
    _In_ const void* state);

static ebpf_result_t
_ebpf_link_instance_invoke_batch_end(_In_ const void* extension_client_binding_context, _Inout_ void* state);

typedef enum _ebpf_link_dispatch_table_version
{
    EBPF_LINK_DISPATCH_TABLE_CURRENT_VERSION = 1, ///< Initial version of the dispatch table.
    EBPF_LINK_DISPATCH_TABLE_VERSION =
        EBPF_LINK_DISPATCH_TABLE_CURRENT_VERSION, ///< Current version of the dispatch table.
} ebpf_link_dispatch_table_version_t;

static const ebpf_extension_program_dispatch_table_t _ebpf_link_dispatch_table = {
    EBPF_LINK_DISPATCH_TABLE_VERSION,
    4, // Count of functions. This should be updated when new functions are added.
    _ebpf_link_instance_invoke,
    _ebpf_link_instance_invoke_batch_begin,
    _ebpf_link_instance_invoke_batch,
    _ebpf_link_instance_invoke_batch_end,
};

// Assert that the invoke function is aligned with ebpf_extension_dispatch_table_t->function.
C_ASSERT(
    EBPF_OFFSET_OF(ebpf_extension_dispatch_table_t, function) ==
    EBPF_OFFSET_OF(ebpf_extension_program_dispatch_table_t, ebpf_program_invoke_function));

NTSTATUS
_ebpf_link_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    EBPF_LOG_ENTRY();

    NTSTATUS status;
    ebpf_link_t* link = (ebpf_link_t*)client_context;
    void* provider_binding_context;
    void* provider_dispatch;
    const ebpf_attach_provider_data_t* attach_provider_data =
        (const ebpf_attach_provider_data_t*)provider_registration_instance->NpiSpecificCharacteristics;

    bool lock_held = false;

    ebpf_lock_state_t state = ebpf_lock_lock(&link->lock);
    lock_held = true;

    UNREFERENCED_PARAMETER(nmr_binding_handle);

    // Verify that that the provider is using the same version of the extension as the client.
    if (!ebpf_validate_attach_provider_data(attach_provider_data)) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_LINK,
            "Attach provider data version is not compatible.",
            attach_provider_data->header.version,
            attach_provider_data->header.size);

        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    if (provider_registration_instance->ModuleId->Type != MIT_GUID) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_LINK, "Attach provider ModuleId type is not GUID.");
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    if (memcmp(&provider_registration_instance->ModuleId->Guid, &link->attach_type, sizeof(link->attach_type)) != 0) {
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_VERBOSE,
            EBPF_TRACELOG_KEYWORD_LINK,
            "Attach provider ModuleId does not match link.",
            &provider_registration_instance->ModuleId->Guid,
            &link->attach_type);
        status = STATUS_NOINTERFACE;
        goto Done;
    }

    if (memcmp(&attach_provider_data->supported_program_type, &link->program_type, sizeof(link->program_type)) != 0) {
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_VERBOSE,
            EBPF_TRACELOG_KEYWORD_LINK,
            "Attach provider program type does not match link.",
            &provider_registration_instance->ModuleId->Guid,
            &link->attach_type);
        status = STATUS_NOINTERFACE;
        goto Done;
    }

    // Only one provider can be attached to a link.
    if (link->provider_attached) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_LINK,
            "Attach provider called on link with provider already attached.");
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    link->link_type = attach_provider_data->link_type;
    link->bpf_attach_type = attach_provider_data->bpf_attach_type;

    ebpf_lock_unlock(&link->lock, state);
    lock_held = false;

    status = NmrClientAttachProvider(
        nmr_binding_handle, link, &_ebpf_link_dispatch_table, &provider_binding_context, &provider_dispatch);

    if (!NT_SUCCESS(status)) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_LINK, "NmrClientAttachProvider failed", status);
        goto Done;
    }

    state = ebpf_lock_lock(&link->lock);
    lock_held = true;
    link->provider_attached = true;

Done:
    if (lock_held)
        ebpf_lock_unlock(&link->lock, state);

    EBPF_RETURN_NTSTATUS(status);
}

NTSTATUS
_ebpf_link_client_detach_provider(void* client_binding_context)
{
    EBPF_LOG_ENTRY();

    ebpf_link_t* link = (ebpf_link_t*)client_binding_context;
    ebpf_lock_state_t state = ebpf_lock_lock(&link->lock);
    link->provider_attached = false;
    ebpf_lock_unlock(&link->lock, state);
    EBPF_LOG_EXIT();
    return STATUS_SUCCESS;
}

static void
_ebpf_link_free(_Frees_ptr_ ebpf_core_object_t* object)
{
    ebpf_link_t* link = (ebpf_link_t*)object;
    ebpf_free((void*)link->client_data.data);
    ebpf_lock_destroy(&link->lock);
    ebpf_epoch_free(link);
}

_Must_inspect_result_ ebpf_result_t
ebpf_link_create(
    ebpf_attach_type_t attach_type,
    _In_reads_(context_data_length) const uint8_t* context_data,
    size_t context_data_length,
    _Outptr_ ebpf_link_t** link)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t retval;
    bool lock_held = false;
    ebpf_link_t* local_link = NULL;
    GUID module_id;

    retval = ebpf_guid_create(&module_id);
    if (retval != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }

    local_link = ebpf_epoch_allocate_with_tag(sizeof(ebpf_link_t), EBPF_POOL_TAG_LINK);
    if (local_link == NULL) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }

    ebpf_lock_create(&local_link->lock);

    ebpf_lock_state_t state = ebpf_lock_lock(&local_link->lock);
    lock_held = true;

    local_link->client_data.header.size = context_data_length;

    if (context_data_length > 0) {
        local_link->client_data.data = ebpf_allocate_with_tag(context_data_length, EBPF_POOL_TAG_LINK);
        if (!local_link->client_data.data) {
            retval = EBPF_NO_MEMORY;
            goto Exit;
        }
        memcpy((void*)local_link->client_data.data, context_data, context_data_length);
    }

    local_link->module_id.Guid = module_id;
    local_link->module_id.Type = MIT_GUID;
    local_link->module_id.Length = sizeof(local_link->module_id);
    local_link->attach_type = attach_type;
    local_link->state = EBPF_LINK_STATE_INITIAL;

    local_link->client_characteristics = _ebpf_link_client_characteristics;
    local_link->client_characteristics.ClientRegistrationInstance.ModuleId = &local_link->module_id;
    local_link->client_characteristics.ClientRegistrationInstance.NpiSpecificCharacteristics = &local_link->client_data;

    ebpf_lock_unlock(&local_link->lock, state);
    lock_held = false;

    // Note: This must be the last thing done in this function as it inserts the object into the global list.
    // After this point, the object can be accessed by other threads.
    ebpf_result_t result = EBPF_OBJECT_INITIALIZE(&local_link->object, EBPF_OBJECT_LINK, _ebpf_link_free, NULL, NULL);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_ERROR(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_LINK, "ebpf_object_initialize failed for link", result);
        retval = EBPF_NO_MEMORY;
        goto Exit;
    }

    *link = local_link;
    local_link = NULL;
    retval = EBPF_SUCCESS;

Exit:
    if (lock_held) {
        ebpf_lock_unlock(&local_link->lock, state);
    }
    if (local_link) {
        _ebpf_link_free(&local_link->object);
    }

    EBPF_RETURN_RESULT(retval);
}

_Must_inspect_result_ ebpf_result_t
ebpf_link_attach_program(_Inout_ ebpf_link_t* link, _Inout_ ebpf_program_t* program)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value = EBPF_SUCCESS;
    bool lock_held = false;
    bool link_attached_to_program = false;
    ebpf_lock_state_t state = 0;

    state = ebpf_lock_lock(&link->lock);
    lock_held = true;

    // If the link is already attached, fail.
    if (link->state != EBPF_LINK_STATE_INITIAL) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_LINK, "Link is already attached to a program.");
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }
    _ebpf_link_set_state(link, EBPF_LINK_STATE_ATTACHING);

    ebpf_assert(link->program == NULL);

    link->program = program;
    link->program_type = ebpf_program_type_uuid(link->program);

    // Attach the program to the link.
    ebpf_program_attach_link(program, link);
    link_attached_to_program = true;

    ebpf_lock_unlock(&link->lock, state);
    lock_held = false;

    NTSTATUS status = NmrRegisterClient(&link->client_characteristics, link, &link->nmr_client_handle);
    if (status != STATUS_SUCCESS) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_LINK, "NmrRegisterClient failed", status);
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    // From this point on, the link is attached to the program and can be invoked.
    state = ebpf_lock_lock(&link->lock);
    lock_held = true;

    if (!link->provider_attached) {
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_LINK,
            "Program failed to attach to extension hook.",
            &link->program_type,
            &link->attach_type);
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }
    _ebpf_link_set_state(link, EBPF_LINK_STATE_ATTACHED);

Done:
    if (return_value != EBPF_SUCCESS) {
        if (!lock_held) {
            ebpf_lock_lock(&link->lock);
            lock_held = true;
        }

        if (link->nmr_client_handle) {
            _ebpf_link_set_state(link, EBPF_LINK_STATE_DETACHING);
            ebpf_lock_unlock(&link->lock, state);
            lock_held = false;

            status = NmrDeregisterClient(link->nmr_client_handle);
            if (status == STATUS_PENDING) {
                NmrWaitForClientDeregisterComplete(link->nmr_client_handle);
            } else {
                ebpf_assert(status == STATUS_SUCCESS);
            }

            state = ebpf_lock_lock(&link->lock);
            _ebpf_link_set_state(link, EBPF_LINK_STATE_DETACHED);
            lock_held = true;
            link->nmr_client_handle = NULL;
        }

        if (link_attached_to_program) {
            ebpf_program_detach_link(program, link);
            link_attached_to_program = false;
            link->program = NULL;
        }
    }

    if (lock_held) {
        ebpf_lock_unlock(&link->lock, state);
    }

    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_link_detach_program(_Inout_ ebpf_link_t* link)
{
    EBPF_LOG_ENTRY();
    ebpf_lock_state_t state;
    bool lock_held = false;

    EBPF_OBJECT_ACQUIRE_REFERENCE(&link->object);

    state = ebpf_lock_lock(&link->lock);
    lock_held = true;

    if (link->state != EBPF_LINK_STATE_ATTACHED) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_LINK, "Link is not attached to a program.");
        goto Done;
    }

    _ebpf_link_set_state(link, EBPF_LINK_STATE_DETACHING);

    ebpf_lock_unlock(&link->lock, state);
    lock_held = false;

    NTSTATUS status = NmrDeregisterClient(link->nmr_client_handle);
    if (status == STATUS_PENDING) {
        NmrWaitForClientDeregisterComplete(link->nmr_client_handle);
    } else {
        ebpf_assert(status == STATUS_SUCCESS);
    }

    // The link is now detached from the attach provider. Program can no longer be invoked.

    state = ebpf_lock_lock(&link->lock);

    _ebpf_link_set_state(link, EBPF_LINK_STATE_DETACHED);
    lock_held = true;

    link->nmr_client_handle = NULL;

    ebpf_program_detach_link(link->program, link);

    ebpf_free((void*)link->client_data.data);

    link->client_data.data = NULL;
    link->client_data.header.size = 0;
    link->program = NULL;

Done:
    if (lock_held) {
        ebpf_lock_unlock(&link->lock, state);
    }

    EBPF_OBJECT_RELEASE_REFERENCE(&link->object);

    EBPF_RETURN_VOID();
}

static ebpf_result_t
_ebpf_link_instance_invoke(
    _In_ const void* extension_client_binding_context, _Inout_ void* program_context, _Out_ uint32_t* result)
{
    ebpf_execution_context_state_t state = {0};
    ebpf_result_t return_value;
    return_value = _ebpf_link_instance_invoke_batch_begin(
        extension_client_binding_context, sizeof(ebpf_execution_context_state_t), &state);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = _ebpf_link_instance_invoke_batch(extension_client_binding_context, program_context, result, &state);
    (void)_ebpf_link_instance_invoke_batch_end(extension_client_binding_context, &state);

Done:
    return return_value;
}

static ebpf_result_t
_ebpf_link_instance_invoke_batch_begin(
    _In_ const void* client_binding_context, size_t state_size, _Out_writes_(state_size) void* state)
{
    UNREFERENCED_PARAMETER(client_binding_context);
    ebpf_execution_context_state_t* execution_context_state = (ebpf_execution_context_state_t*)state;
    bool epoch_entered = false;
    ebpf_result_t return_value;
    if (state_size < sizeof(ebpf_execution_context_state_t)) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    memset(execution_context_state, 0, sizeof(ebpf_execution_context_state_t));

    ebpf_get_execution_context_state(execution_context_state);
    return_value = ebpf_state_store(ebpf_program_get_state_index(), (uintptr_t)state, execution_context_state);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    ebpf_epoch_enter((ebpf_epoch_state_t*)(execution_context_state->epoch_state));
    epoch_entered = true;

Done:
    if (return_value != EBPF_SUCCESS && epoch_entered) {
        ebpf_epoch_exit((ebpf_epoch_state_t*)(execution_context_state->epoch_state));
    }

    return return_value;
}

static ebpf_result_t
_ebpf_link_instance_invoke_batch_end(_In_ const void* extension_client_binding_context, _Inout_ void* state)
{
    UNREFERENCED_PARAMETER(extension_client_binding_context);
    ebpf_execution_context_state_t* execution_context_state = (ebpf_execution_context_state_t*)state;
    ebpf_assert_success(ebpf_state_store(ebpf_program_get_state_index(), 0, execution_context_state));
    ebpf_epoch_exit((ebpf_epoch_state_t*)(execution_context_state->epoch_state));
    return EBPF_SUCCESS;
}

static ebpf_result_t
_ebpf_link_instance_invoke_batch(
    _In_ const void* client_binding_context,
    _Inout_ void* program_context,
    _Out_ uint32_t* result,
    _In_ const void* state)
{
    // No function entry exit traces as this is a high volume function.
    ebpf_result_t return_value;
    ebpf_link_t* link = (ebpf_link_t*)client_binding_context;

    return_value = ebpf_program_invoke(link->program, program_context, result, (ebpf_execution_context_state_t*)state);

    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_link_get_info(
    _In_ const ebpf_link_t* link, _Out_writes_to_(*info_size, *info_size) uint8_t* buffer, _Inout_ uint16_t* info_size)
{
    EBPF_LOG_ENTRY();
    struct bpf_link_info* info = (struct bpf_link_info*)buffer;

    if (*info_size < sizeof(*info)) {
        EBPF_RETURN_RESULT(EBPF_INSUFFICIENT_BUFFER);
    }

    ebpf_lock_state_t state = ebpf_lock_lock((ebpf_lock_t*)&link->lock);

    memset(info, 0, sizeof(*info));
    info->id = link->object.id;
    info->prog_id = (link->program) ? ((ebpf_core_object_t*)link->program)->id : EBPF_ID_NONE;
    info->type = link->link_type;
    info->program_type_uuid = link->program_type;
    info->attach_type_uuid = link->attach_type;
    info->attach_type = link->bpf_attach_type;

    // Copy any additional parameters.
    size_t size = sizeof(struct bpf_link_info) - FIELD_OFFSET(struct bpf_link_info, attach_data);
    if ((link->client_data.header.size > 0) && (link->client_data.header.size <= size)) {
        memcpy(&info->attach_data, link->client_data.data, link->client_data.header.size);
    }

    ebpf_lock_unlock((ebpf_lock_t*)&link->lock, state);

    *info_size = sizeof(*info);
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

/**
 * @brief Set and validate the link state.
 *
 * @param[in] link Link to set state on.
 * @param[in] new_state New state to set.
 */
_Requires_lock_held_(link->lock) static void _ebpf_link_set_state(
    _Inout_ ebpf_link_t* link, ebpf_link_state_t new_state)
{
    ebpf_link_state_t old_state = link->state;
    switch (new_state) {
    case EBPF_LINK_STATE_INITIAL:
        ebpf_assert(old_state == EBPF_LINK_STATE_ATTACHING);
        break;
    case EBPF_LINK_STATE_ATTACHING:
        ebpf_assert(old_state == EBPF_LINK_STATE_INITIAL);
        break;
    case EBPF_LINK_STATE_ATTACHED:
        ebpf_assert(old_state == EBPF_LINK_STATE_ATTACHING);
        break;
    case EBPF_LINK_STATE_DETACHING:
        ebpf_assert(old_state == EBPF_LINK_STATE_ATTACHED || old_state == EBPF_LINK_STATE_ATTACHING);
        break;
    case EBPF_LINK_STATE_DETACHED:
        // Program is unlinked from a provider.
        ebpf_assert(old_state == EBPF_LINK_STATE_DETACHING);
        break;
    default:
        ebpf_assert(!"Invalid link state");
        break;
    }
    UNREFERENCED_PARAMETER(old_state);
    link->state = new_state;
}
