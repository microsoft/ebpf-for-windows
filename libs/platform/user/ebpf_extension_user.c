// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"

#define EBPF_EXTENSION_TABLE_BUCKET_COUNT 64

volatile ebpf_handle_t next_handle = 1;

#ifndef GUID_NULL
static const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

static ebpf_handle_t
_ebpf_get_next_handle()
{
#ifdef _WIN64
    return InterlockedIncrement64(&next_handle);
#else
    return InterlockedIncrement(&next_handle);
#endif
}

typedef struct _ebpf_extension_client
{
    GUID npi_id;
    GUID client_module_id;
    ebpf_handle_t nmr_binding_handle;
    GUID expected_provider_module_id;
    void* extension_client_context;
    const ebpf_extension_data_t* client_data;
    const ebpf_extension_dispatch_table_t* client_dispatch_table;
} ebpf_extension_client_t;

typedef struct _ebpf_extension_provider
{
    GUID interface_id;
    GUID provider_module_id;
    void* provider_binding_context;
    const ebpf_extension_data_t* provider_data;
    const ebpf_extension_dispatch_table_t* provider_dispatch_table;
    void* callback_context;
    ebpf_provider_client_attach_callback_t client_attach_callback;
    ebpf_provider_client_detach_callback_t client_detach_callback;
    ebpf_hash_table_t* client_table;
} ebpf_extension_provider_t;

static ebpf_lock_t _ebpf_provider_table_lock = {0};
static _Requires_lock_held_(&_ebpf_provider_table_lock) ebpf_hash_table_t* _ebpf_provider_table = NULL;

ebpf_result_t
ebpf_extension_load(
    _Outptr_ ebpf_extension_client_t** client_context,
    _In_ const GUID* interface_id,
    _In_ const GUID* expected_provider_module_id,
    _In_ const GUID* client_module_id,
    _In_ void* extension_client_context,
    _In_opt_ const ebpf_extension_data_t* client_data,
    _In_opt_ const ebpf_extension_dispatch_table_t* client_dispatch_table,
    _Outptr_opt_ void** provider_binding_context,
    _Outptr_opt_ const ebpf_extension_data_t** provider_data,
    _Outptr_opt_ const ebpf_extension_dispatch_table_t** provider_dispatch_table,
    _In_opt_ ebpf_extension_change_callback_t extension_changed)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_lock_state_t state = 0;
    ebpf_extension_provider_t* local_extension_provider = NULL;
    ebpf_extension_provider_t** hash_table_find_result = NULL;
    ebpf_extension_client_t* local_extension_client = NULL;

    state = ebpf_lock_lock(&_ebpf_provider_table_lock);

    if (provider_binding_context == NULL) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (!_ebpf_provider_table) {
        return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
        goto Done;
    }

    local_extension_client = ebpf_allocate(sizeof(ebpf_extension_client_t));
    if (!local_extension_client) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(local_extension_client, 0, sizeof(ebpf_extension_client_t));
    local_extension_client->extension_client_context = extension_client_context;
    local_extension_client->client_data = client_data;
    local_extension_client->client_dispatch_table = client_dispatch_table;
    local_extension_client->nmr_binding_handle = _ebpf_get_next_handle();
    local_extension_client->npi_id = *interface_id;
    local_extension_client->expected_provider_module_id = *expected_provider_module_id;
    local_extension_client->client_module_id = *client_module_id;

    return_value = ebpf_hash_table_find(
        _ebpf_provider_table, (const uint8_t*)expected_provider_module_id, (uint8_t**)&hash_table_find_result);
    if (return_value != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Provider not found", *expected_provider_module_id);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }
    local_extension_provider = *hash_table_find_result;

    return_value = ebpf_hash_table_update(
        local_extension_provider->client_table,
        (const uint8_t*)&local_extension_client->client_module_id,
        (const uint8_t*)&local_extension_client,
        EBPF_HASH_TABLE_OPERATION_INSERT);
    if (return_value != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "ebpf_hash_table_update failed", return_value);
        goto Done;
    }

    if (local_extension_provider->client_attach_callback) {
        return_value = local_extension_provider->client_attach_callback(
            local_extension_client->nmr_binding_handle,
            local_extension_provider->callback_context,
            &local_extension_client->client_module_id,
            local_extension_client,
            client_data,
            client_dispatch_table);
        if (return_value != EBPF_SUCCESS) {
            return_value = EBPF_EXTENSION_FAILED_TO_LOAD;
            goto Done;
        }
    }
    *client_context = local_extension_client;
    local_extension_client = NULL;
    if (provider_binding_context)
        *provider_binding_context = local_extension_provider->provider_binding_context;
    if (provider_data != NULL)
        *provider_data = local_extension_provider->provider_data;
    if (provider_dispatch_table != NULL)
        *provider_dispatch_table = local_extension_provider->provider_dispatch_table;

    // Invoke extension changed on client.
    if ((extension_changed != NULL) && (provider_data != NULL))
        extension_changed(extension_client_context, provider_binding_context, *provider_data);

Done:
    if (local_extension_provider && local_extension_client) {
        ebpf_hash_table_delete(
            local_extension_provider->client_table, (const uint8_t*)&local_extension_client->client_module_id);
    }

    ebpf_lock_unlock(&_ebpf_provider_table_lock, state);
    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_extension_unload(_Frees_ptr_opt_ ebpf_extension_client_t* client_context)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_lock_state_t state;
    ebpf_extension_provider_t** hash_table_find_result = NULL;
    ebpf_extension_provider_t* local_extension_provider = NULL;

    if (!client_context)
        EBPF_RETURN_VOID();

    state = ebpf_lock_lock(&_ebpf_provider_table_lock);

    if (!_ebpf_provider_table) {
        goto Done;
    }

    return_value = ebpf_hash_table_find(
        _ebpf_provider_table,
        (const uint8_t*)&client_context->expected_provider_module_id,
        (uint8_t**)&hash_table_find_result);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }
    local_extension_provider = *hash_table_find_result;

    if (local_extension_provider->client_detach_callback) {
        return_value = local_extension_provider->client_detach_callback(
            local_extension_provider->callback_context, &client_context->client_module_id);
    }
    if (return_value != EBPF_PENDING) {
        ebpf_hash_table_delete(
            local_extension_provider->client_table, (const uint8_t*)&client_context->client_module_id);
    }

Done:
    ebpf_free(client_context);
    ebpf_lock_unlock(&_ebpf_provider_table_lock, state);
    EBPF_RETURN_VOID();
}

void
ebpf_provider_detach_client_complete(_In_ const GUID* interface_id, ebpf_handle_t nmr_binding_handle)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_lock_state_t state;
    ebpf_extension_provider_t** hash_table_find_result = NULL;
    ebpf_extension_provider_t* local_extension_provider = NULL;
    GUID module_id = GUID_NULL;
    ebpf_extension_client_t* client = NULL;

    state = ebpf_lock_lock(&_ebpf_provider_table_lock);

    if (!_ebpf_provider_table) {
        goto Done;
    }

    return_value =
        ebpf_hash_table_find(_ebpf_provider_table, (const uint8_t*)interface_id, (uint8_t**)&hash_table_find_result);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }
    local_extension_provider = *hash_table_find_result;

    for (;;) {
        return_value = ebpf_hash_table_next_key_and_value(
            local_extension_provider->client_table,
            (const uint8_t*)(IsEqualGUID(&module_id, &GUID_NULL) ? NULL : &module_id),
            (uint8_t*)&module_id,
            (uint8_t**)&client);

        if (return_value != EBPF_SUCCESS) {
            break;
        }

        if (client->nmr_binding_handle == nmr_binding_handle) {
            // Found the matching entry. Delete it.
            ebpf_hash_table_delete(local_extension_provider->client_table, (const uint8_t*)&client->client_module_id);
            break;
        }
    }

Done:
    ebpf_lock_unlock(&_ebpf_provider_table_lock, state);
    EBPF_RETURN_VOID();
}

void*
ebpf_extension_get_client_context(_In_ const void* extension_client_binding_context)
{
    void* local_extension_client_context = NULL;
    ebpf_extension_client_t* local_client_context = (ebpf_extension_client_t*)extension_client_binding_context;
    if (local_client_context != NULL)
        local_extension_client_context = local_client_context->extension_client_context;

    return local_extension_client_context;
}

GUID
ebpf_extension_get_provider_guid(_In_ const void* extension_client_binding_context)
{
    ebpf_extension_client_t* local_client_context = (ebpf_extension_client_t*)extension_client_binding_context;
    return local_client_context->npi_id;
}

#pragma warning(push)
#pragma warning(disable : 6101) // ebpf_free at exit
ebpf_result_t
ebpf_provider_load(
    _Outptr_ ebpf_extension_provider_t** provider_context,
    _In_ const GUID* interface_id,
    _In_ const GUID* provider_module_id,
    _In_opt_ void* provider_binding_context,
    _In_opt_ const ebpf_extension_data_t* provider_data,
    _In_opt_ const ebpf_extension_dispatch_table_t* provider_dispatch_table,
    _In_opt_ void* callback_context,
    _In_opt_ ebpf_provider_client_attach_callback_t client_attach_callback,
    _In_opt_ ebpf_provider_client_detach_callback_t client_detach_callback)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_lock_state_t state;
    ebpf_extension_provider_t* local_extension_provider = NULL;
    state = ebpf_lock_lock(&_ebpf_provider_table_lock);

    if (!_ebpf_provider_table) {
        return_value = ebpf_hash_table_create(
            &_ebpf_provider_table,
            ebpf_allocate,
            ebpf_free,
            sizeof(GUID),
            sizeof(void*),
            EBPF_EXTENSION_TABLE_BUCKET_COUNT,
            NULL);
        if (return_value != EBPF_SUCCESS)
            goto Done;
    }

    return_value = ebpf_hash_table_find(
        _ebpf_provider_table, (const uint8_t*)provider_module_id, (uint8_t**)&local_extension_provider);
    if (return_value == EBPF_SUCCESS) {
        return_value = EBPF_OBJECT_ALREADY_EXISTS;
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Provider already loaded", *interface_id);

        local_extension_provider = NULL;
        goto Done;
    }

    local_extension_provider = ebpf_allocate(sizeof(ebpf_extension_provider_t));
    if (!local_extension_provider) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }
    memset(local_extension_provider, 0, sizeof(ebpf_extension_provider_t));

    local_extension_provider->interface_id = *interface_id;
    local_extension_provider->provider_module_id = *provider_module_id;
    local_extension_provider->provider_binding_context = provider_binding_context;
    local_extension_provider->provider_data = provider_data;
    local_extension_provider->provider_dispatch_table = provider_dispatch_table;
    local_extension_provider->callback_context = callback_context;
    local_extension_provider->client_attach_callback = client_attach_callback;
    local_extension_provider->client_detach_callback = client_detach_callback;

    return_value = ebpf_hash_table_create(
        &local_extension_provider->client_table,
        ebpf_allocate,
        ebpf_free,
        sizeof(GUID),
        sizeof(void*),
        EBPF_EXTENSION_TABLE_BUCKET_COUNT,
        NULL);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    return_value = ebpf_hash_table_update(
        _ebpf_provider_table,
        (const uint8_t*)provider_module_id,
        (const uint8_t*)&local_extension_provider,
        EBPF_HASH_TABLE_OPERATION_INSERT);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    *provider_context = local_extension_provider;
    local_extension_provider = NULL;

Done:
    ebpf_lock_unlock(&_ebpf_provider_table_lock, state);
    ebpf_free(local_extension_provider);
    EBPF_RETURN_RESULT(return_value);
}
#pragma warning(pop)

void
ebpf_provider_unload(_Frees_ptr_opt_ ebpf_extension_provider_t* provider_context)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    ebpf_lock_state_t state;
    ebpf_extension_provider_t* local_extension_provider = NULL;
    GUID next_key;

    if (!provider_context)
        EBPF_RETURN_VOID();

    state = ebpf_lock_lock(&_ebpf_provider_table_lock);

    if (!_ebpf_provider_table) {
        goto Done;
    }

    ebpf_hash_table_delete(_ebpf_provider_table, (const uint8_t*)&provider_context->provider_module_id);

    return_value = ebpf_hash_table_next_key(_ebpf_provider_table, NULL, (uint8_t*)&next_key);
    if (return_value == EBPF_NO_MORE_KEYS) {
        ebpf_hash_table_destroy(_ebpf_provider_table);
        _ebpf_provider_table = NULL;
    }

Done:
    ebpf_lock_unlock(&_ebpf_provider_table_lock, state);
    ebpf_free(local_extension_provider);
    EBPF_RETURN_VOID();
}
