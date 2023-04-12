// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_object.h"
#include "ebpf_platform.h"
#include "ebpf_program.h"

/**
 * @brief State of the link between program and provider.
 * The link starts in IDLE state. When a program is attached to a provider, the
 * state transitions to ATTACHING. If the provider is not found, the state
 * transitions to IDLE. If the provider is found, the state transitions to
 * ATTACHED. When a program is detached from a provider, the state transitions
 * to DETACHING. Once the provider is notified, the state transitions to IDLE.
 */
typedef enum _ebpf_link_state
{
    EBPF_LINK_STATE_IDLE,      ///< Program is not attached to any provider.
    EBPF_LINK_STATE_ATTACHING, ///< Program is in the process of getting attached.
    EBPF_LINK_STATE_ATTACHED,  ///< Program is attached to a provider.
    EBPF_LINK_STATE_DETACHING, ///< Program is in the process of getting detached.
} ebpf_link_state_t;

typedef struct _ebpf_link
{
    ebpf_core_object_t object;
    ebpf_program_t* program;

    ebpf_attach_type_t attach_type;
    bpf_attach_type_t bpf_attach_type;
    enum bpf_link_type link_type;
    ebpf_program_type_t program_type;
    ebpf_extension_data_t client_data;
    ebpf_extension_client_t* extension_client_context;
    ebpf_lock_t attach_lock;
    ebpf_link_state_t state;
    void* provider_binding_context;
} ebpf_link_t;

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

const typedef struct _ebpf_link_dispatch_table
{
    ebpf_extension_dispatch_table_t;
    _ebpf_extension_dispatch_function new_functions[];
} ebpf_link_dispatch_table_t;

static ebpf_link_dispatch_table_t _ebpf_link_dispatch_table = {
    EBPF_LINK_DISPATCH_TABLE_VERSION,
    4, // Count of functions. This should be updated when new functions are added.
    _ebpf_link_instance_invoke,
    _ebpf_link_instance_invoke_batch_begin,
    _ebpf_link_instance_invoke_batch,
    _ebpf_link_instance_invoke_batch_end,
};

// Assert that new_functions is aligned with ebpf_extension_dispatch_table_t->function.
C_ASSERT(sizeof(ebpf_extension_dispatch_table_t) == EBPF_OFFSET_OF(ebpf_link_dispatch_table_t, new_functions));

static void
_ebpf_link_free(_Frees_ptr_ ebpf_core_object_t* object)
{
    ebpf_link_t* link = (ebpf_link_t*)object;
    ebpf_free(link->client_data.data);
    ebpf_lock_destroy(&link->attach_lock);
    ebpf_epoch_free(link);
}

_Must_inspect_result_ ebpf_result_t
ebpf_link_create(_Outptr_ ebpf_link_t** link)
{
    EBPF_LOG_ENTRY();
    *link = ebpf_epoch_allocate_with_tag(sizeof(ebpf_link_t), EBPF_POOL_TAG_LINK);
    if (*link == NULL) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }

    memset(*link, 0, sizeof(ebpf_link_t));

    ebpf_result_t result = ebpf_object_initialize(&(*link)->object, EBPF_OBJECT_LINK, _ebpf_link_free, NULL);
    if (result != EBPF_SUCCESS) {
        ebpf_epoch_free(link);
        EBPF_RETURN_RESULT(result);
    }

    (*link)->state = EBPF_LINK_STATE_IDLE;

    ebpf_lock_create(&(*link)->attach_lock);
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

_Must_inspect_result_ ebpf_result_t
ebpf_link_initialize(
    _Inout_ ebpf_link_t* link,
    ebpf_attach_type_t attach_type,
    _In_reads_(context_data_length) const uint8_t* context_data,
    size_t context_data_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;

    link->client_data.version = 0;
    link->client_data.size = context_data_length;

    if (context_data_length > 0) {
        link->client_data.data = ebpf_allocate_with_tag(context_data_length, EBPF_POOL_TAG_LINK);
        if (!link->client_data.data) {
            return_value = EBPF_NO_MEMORY;
            goto Exit;
        }
        memcpy(link->client_data.data, context_data, context_data_length);
    }

    link->attach_type = attach_type;

    return_value = EBPF_SUCCESS;
Exit:
    EBPF_RETURN_RESULT(return_value);
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
        result = EBPF_SUCCESS;
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

    // If the link is not in idle state, then it is either:
    // 1. Attaching to a program.
    // 2. Detaching from a program.
    // 3. Attached to a program.
    if (link->state != EBPF_LINK_STATE_IDLE) {
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
    link->state = EBPF_LINK_STATE_ATTACHING;

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

    if (return_value == EBPF_SUCCESS) {
        ebpf_assert(link->state == EBPF_LINK_STATE_ATTACHING);
        ebpf_assert(link_is_attaching);
        ebpf_assert(link->program != NULL);
        link->state = EBPF_LINK_STATE_ATTACHED;
    } else {
        if (link_is_attaching) {
            link->state = EBPF_LINK_STATE_IDLE;
        }
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

    ebpf_object_acquire_reference((ebpf_core_object_t*)link);

    state = ebpf_lock_lock(&link->attach_lock);

    if (link->state == EBPF_LINK_STATE_ATTACHED) {
        link->state = EBPF_LINK_STATE_DETACHING;
        // This thread is responsible for detaching the link from the program.
        link_is_detaching = true;
        program = link->program;
        ebpf_assert(program != NULL);
    }
    if (link->state == EBPF_LINK_STATE_IDLE) {
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

    link->state = EBPF_LINK_STATE_IDLE;

    link->extension_client_context = NULL;

    ebpf_free(link->client_data.data);

    link->client_data.data = NULL;
    link->client_data.size = 0;
    link->program = NULL;
    ebpf_lock_unlock(&link->attach_lock, state);

Done:
    ebpf_object_release_reference((ebpf_core_object_t*)link);

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

    *info_size = sizeof(*info);
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}
