// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_LINK

#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_object.h"
#include "ebpf_platform.h"
#include "ebpf_program.h"

/**
 * @brief State of the link between program and provider.
 * Legal state transitions are:
 * 1. EBPF_LINK_STATE_INITIAL -> EBPF_LINK_STATE_ATTACHING - In ebpf_link_attach_program when the program is being
 * linked.
 * 2. EBPF_LINK_STATE_ATTACHING -> EBPF_LINK_STATE_ATTACHED - In _ebpf_link_extension_changed_callback when the provider
 * attaches.
 * 3. EBPF_LINK_STATE_ATTACHED -> EBPF_LINK_STATE_ATTACHING - In _ebpf_link_extension_changed_callback when the provider
 * is reattaching.
 * 4. EBPF_LINK_STATE_ATTACHED -> EBPF_LINK_STATE_DETACHING - In ebpf_link_detach_program when the program is being
 * unlinked.
 * 5. EBPF_LINK_STATE_DETACHING -> EBPF_LINK_STATE_DETACHED - In _ebpf_link_extension_changed_callback when the provider
 * detaches.
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
    ebpf_program_t* program;

    ebpf_attach_type_t attach_type;
    bpf_attach_type_t bpf_attach_type;
    enum bpf_link_type link_type;
    ebpf_program_type_t program_type;
    _Guarded_by_(attach_lock) ebpf_extension_data_t client_data;
    ebpf_extension_client_t* extension_client_context;
    ebpf_lock_t attach_lock;
    _Guarded_by_(attach_lock) ebpf_link_state_t state;
    void* provider_binding_context;
} ebpf_link_t;

_Requires_lock_held_(link->attach_lock) static void _ebpf_link_set_state(
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
    EBPF_LINK_DISPATCH_TABLE_VERSION_1 = 1,                                ///< Initial version of the dispatch table.
    EBPF_LINK_DISPATCH_TABLE_VERSION = EBPF_LINK_DISPATCH_TABLE_VERSION_1, ///< Current version of the dispatch table.
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

static void
_ebpf_link_free(_Frees_ptr_ ebpf_core_object_t* object)
{
    ebpf_link_t* link = (ebpf_link_t*)object;
    ebpf_free(link->client_data.data);
    ebpf_lock_destroy(&link->attach_lock);
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
    ebpf_link_t* local_link = NULL;
    local_link = ebpf_epoch_allocate_with_tag(sizeof(ebpf_link_t), EBPF_POOL_TAG_LINK);
    if (local_link == NULL) {
        retval = EBPF_NO_MEMORY;
        goto Exit;
    }

    memset(local_link, 0, sizeof(ebpf_link_t));

    local_link->state = EBPF_LINK_STATE_INITIAL;

    local_link->client_data.version = 0;
    local_link->client_data.size = context_data_length;

    if (context_data_length > 0) {
        local_link->client_data.data = ebpf_allocate_with_tag(context_data_length, EBPF_POOL_TAG_LINK);
        if (!local_link->client_data.data) {
            retval = EBPF_NO_MEMORY;
            goto Exit;
        }
        memcpy(local_link->client_data.data, context_data, context_data_length);
    }

    local_link->attach_type = attach_type;

    ebpf_lock_create(&local_link->attach_lock);

    // Note: This must be the last thing done in this function as it inserts the object into the global list.
    // After this point, the object can be accessed by other threads.
    ebpf_result_t result = EBPF_OBJECT_INITIALIZE(&local_link->object, EBPF_OBJECT_LINK, _ebpf_link_free, NULL);
    if (result != EBPF_SUCCESS) {
        retval = EBPF_NO_MEMORY;
        goto Exit;
    }

    *link = local_link;
    local_link = NULL;
    retval = EBPF_SUCCESS;

Exit:
    if (local_link) {
        _ebpf_link_free(&local_link->object);
    }

    EBPF_RETURN_RESULT(retval);
}

static ebpf_result_t
_ebpf_link_extension_changed_callback(
    _In_ const void* client_binding_context, _In_opt_ const ebpf_extension_data_t* provider_data)
{
    ebpf_result_t result;
    ebpf_link_t* link = (ebpf_link_t*)client_binding_context;
    ebpf_lock_state_t state = ebpf_lock_lock(&link->attach_lock);

    // Complete detach.
    if (provider_data == NULL) {
        // Check if the link is in the process of attaching.
        if (link->state == EBPF_LINK_STATE_DETACHING) {
            // If so, complete the detach.
            _ebpf_link_set_state(link, EBPF_LINK_STATE_DETACHED);
        } else if (link->state == EBPF_LINK_STATE_ATTACHED) {
            // If not, mark the link as ready to reattach.
            _ebpf_link_set_state(link, EBPF_LINK_STATE_ATTACHING);
        }
        result = EBPF_SUCCESS;
        goto Done;
    }

    if (link->state != EBPF_LINK_STATE_ATTACHING) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if ((provider_data->version != EBPF_ATTACH_PROVIDER_DATA_VERSION) || (!provider_data->data) ||
        (provider_data->size != sizeof(ebpf_attach_provider_data_t))) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_LINK, "Provider version not supported", link->attach_type);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    ebpf_program_type_t program_type = ebpf_program_type_uuid(link->program);
    ebpf_attach_provider_data_t* attach_provider_data = (ebpf_attach_provider_data_t*)provider_data->data;

    if (memcmp(
            &program_type,
            &attach_provider_data->supported_program_type,
            sizeof(attach_provider_data->supported_program_type)) != 0) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_LINK,
            "Attach failed due to incorrect program type",
            program_type);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    link->program_type = attach_provider_data->supported_program_type;
    link->bpf_attach_type = attach_provider_data->bpf_attach_type;
    link->link_type = attach_provider_data->link_type;
    _ebpf_link_set_state(link, EBPF_LINK_STATE_ATTACHED);
    ebpf_assert(link->program != NULL);

    result = EBPF_SUCCESS;

Done:
    ebpf_lock_unlock(&link->attach_lock, state);
    // Note: As soon as the attach is complete, the program can be invoked.
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_link_attach_program(_Inout_ ebpf_link_t* link, _Inout_ ebpf_program_t* program)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value = EBPF_SUCCESS;
    bool attach_lock_held = false;
    ebpf_lock_state_t state = 0;
    ebpf_extension_data_t* provider_data;
    GUID module_id = {0};
    bool link_is_attaching = false;

    // GUID create must be called at IRQL PASSIVE_LEVEL.
    return_value = ebpf_guid_create(&module_id);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    state = ebpf_lock_lock(&link->attach_lock);
    attach_lock_held = true;

    // If the link is already attached, fail.
    if (link->state != EBPF_LINK_STATE_INITIAL) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }
    // This thread is responsible for attaching the link to the program.
    link_is_attaching = true;

    if (link->program) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    link->program = program;
    ebpf_program_attach_link(program, link);
    _ebpf_link_set_state(link, EBPF_LINK_STATE_ATTACHING);

    ebpf_lock_unlock(&link->attach_lock, state);
    attach_lock_held = false;

    return_value = ebpf_extension_load(
        &(link->extension_client_context),
        &ebpf_hook_extension_interface_id, // Load hook extension.
        &link->attach_type,                // Attach type is the expected provider module Id.
        &module_id,
        link,
        &link->client_data,
        (ebpf_extension_dispatch_table_t*)&_ebpf_link_dispatch_table,
        &(link->provider_binding_context),
        &provider_data,
        NULL,
        _ebpf_link_extension_changed_callback);

    if (return_value != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_LINK,
            "No providers support attach type",
            link->attach_type);
        goto Done;
    }

Done:
    if (!attach_lock_held) {
        state = ebpf_lock_lock(&link->attach_lock);
        attach_lock_held = true;
    }

    if (return_value != EBPF_SUCCESS && link_is_attaching && link->program) {
        ebpf_program_detach_link(program, link);
        link->program = NULL;
    }

    if (return_value != EBPF_SUCCESS) {
        _ebpf_link_set_state(link, EBPF_LINK_STATE_DETACHED);
    }

    if (attach_lock_held) {
        ebpf_lock_unlock(&link->attach_lock, state);
    }
    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_link_detach_program(_Inout_ ebpf_link_t* link)
{
    EBPF_LOG_ENTRY();
    ebpf_lock_state_t state;
    ebpf_program_t* program = NULL;
    bool link_is_detaching = false;

    EBPF_OBJECT_ACQUIRE_REFERENCE((ebpf_core_object_t*)link);

    state = ebpf_lock_lock(&link->attach_lock);

    if (link->state == EBPF_LINK_STATE_ATTACHED || link->state == EBPF_LINK_STATE_ATTACHING) {
        // This thread is responsible for detaching the link from the program.
        _ebpf_link_set_state(link, EBPF_LINK_STATE_DETACHING);
        link_is_detaching = true;
        program = link->program;
        ebpf_assert(program != NULL);
    }

    if (link->state == EBPF_LINK_STATE_INITIAL || link->state == EBPF_LINK_STATE_DETACHED) {
        ebpf_assert(link->program == NULL);
    }

    ebpf_lock_unlock(&link->attach_lock, state);

    if (!link_is_detaching) {
        goto Done;
    }

    // Request the provider to detach.
    ebpf_extension_unload(link->extension_client_context);

    if (program) {
        ebpf_program_detach_link(program, link);
    }

    state = ebpf_lock_lock(&link->attach_lock);

    link->extension_client_context = NULL;

    ebpf_free(link->client_data.data);

    link->client_data.data = NULL;
    link->client_data.size = 0;
    link->program = NULL;
    ebpf_lock_unlock(&link->attach_lock, state);

Done:
    EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)link);

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
    ebpf_assert(return_value == EBPF_SUCCESS);

    return_value = _ebpf_link_instance_invoke_batch_end(extension_client_binding_context, &state);
    ebpf_assert(return_value == EBPF_SUCCESS);

Done:
    return return_value;
}

static ebpf_result_t
_ebpf_link_instance_invoke_batch_begin(
    _In_ const void* extension_client_binding_context, size_t state_size, _Out_writes_(state_size) void* state)
{
    bool epoch_entered = false;
    bool provider_reference_held = false;
    ebpf_result_t return_value;
    ebpf_link_t* link = (ebpf_link_t*)ebpf_extension_get_client_context(extension_client_binding_context);

    if (state_size < sizeof(ebpf_execution_context_state_t)) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    ebpf_get_execution_context_state((ebpf_execution_context_state_t*)state);

    if (link == NULL) {
        GUID npi_id = ebpf_extension_get_provider_guid(extension_client_binding_context);
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_WARNING, EBPF_TRACELOG_KEYWORD_LINK, "Client context is null", npi_id);
        return_value = EBPF_FAILED;
        goto Done;
    }

    ((ebpf_execution_context_state_t*)state)->epoch_state = ebpf_epoch_enter();
    epoch_entered = true;

    ebpf_assert(link->state == EBPF_LINK_STATE_ATTACHED);

    return_value = ebpf_program_reference_providers(link->program);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }
    provider_reference_held = true;

Done:
    if (return_value != EBPF_SUCCESS && provider_reference_held) {
        ebpf_program_dereference_providers(link->program);
    }

    if (return_value != EBPF_SUCCESS && epoch_entered) {
        ebpf_epoch_exit(((ebpf_execution_context_state_t*)state)->epoch_state);
    }

    return return_value;
}

static ebpf_result_t
_ebpf_link_instance_invoke_batch_end(_In_ const void* extension_client_binding_context, _Inout_ void* state)
{
    ebpf_execution_context_state_t* execution_context_state = (ebpf_execution_context_state_t*)state;
    ebpf_link_t* link = (ebpf_link_t*)ebpf_extension_get_client_context(extension_client_binding_context);
    ebpf_program_dereference_providers(link->program);
    ebpf_epoch_exit(execution_context_state->epoch_state);
    return EBPF_SUCCESS;
}

static ebpf_result_t
_ebpf_link_instance_invoke_batch(
    _In_ const void* extension_client_binding_context,
    _Inout_ void* program_context,
    _Out_ uint32_t* result,
    _In_ const void* state)
{
    // No function entry exit traces as this is a high volume function.
    ebpf_result_t return_value = EBPF_SUCCESS;
    ebpf_link_t* link = (ebpf_link_t*)ebpf_extension_get_client_context(extension_client_binding_context);

    ebpf_program_invoke(link->program, program_context, result, (ebpf_execution_context_state_t*)state);

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

    ebpf_lock_state_t state = ebpf_lock_lock((ebpf_lock_t*)&link->attach_lock);

    memset(info, 0, sizeof(*info));
    info->id = link->object.id;
    info->prog_id = (link->program) ? ((ebpf_core_object_t*)link->program)->id : EBPF_ID_NONE;
    info->type = link->link_type;
    info->program_type_uuid = link->program_type;
    info->attach_type_uuid = link->attach_type;
    info->attach_type = link->bpf_attach_type;

    // Copy any additional parameters.
    size_t size = sizeof(struct bpf_link_info) - FIELD_OFFSET(struct bpf_link_info, attach_data);
    if ((link->client_data.size > 0) && (link->client_data.size <= size)) {
        memcpy(&info->attach_data, link->client_data.data, link->client_data.size);
    }

    ebpf_lock_unlock((ebpf_lock_t*)&link->attach_lock, state);

    *info_size = sizeof(*info);
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

/**
 * @brief Set and validate the link state.
 *
 * @param[in] link Link to set state on.
 * @param[in] new_state New state to set.
 */
_Requires_lock_held_(link->attach_lock) static void _ebpf_link_set_state(
    _Inout_ ebpf_link_t* link, ebpf_link_state_t new_state)
{
    ebpf_link_state_t old_state = link->state;
    switch (new_state) {
    case EBPF_LINK_STATE_ATTACHING:
        // Runtime has requested that the program be linked to a provider.
        ebpf_assert(old_state == EBPF_LINK_STATE_INITIAL || old_state == EBPF_LINK_STATE_ATTACHED);
        break;
    case EBPF_LINK_STATE_ATTACHED:
        // Program is linked to a provider.
        ebpf_assert(old_state == EBPF_LINK_STATE_ATTACHING);
        break;
    case EBPF_LINK_STATE_DETACHING:
        // Runtime has requested that the program be unlinked from a provider.
        ebpf_assert(old_state == EBPF_LINK_STATE_ATTACHED || old_state == EBPF_LINK_STATE_ATTACHING);
        break;
    case EBPF_LINK_STATE_DETACHED:
        // Program is unlinked from a provider.
        ebpf_assert(
            old_state == EBPF_LINK_STATE_INITIAL || old_state == EBPF_LINK_STATE_DETACHING ||
            old_state == EBPF_LINK_STATE_ATTACHING);
        break;
    }
    UNREFERENCED_PARAMETER(old_state);
    link->state = new_state;
}
