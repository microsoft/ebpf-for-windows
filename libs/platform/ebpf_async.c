// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_async.h"
#include "ebpf_epoch.h"

typedef struct _ebpf_async_tracker
{
    void (*on_complete)(_Inout_ void*, size_t, ebpf_result_t);
    void* cancellation_context;
    void (*on_cancel)(_Inout_ void*);
} ebpf_async_tracker_t;

static ebpf_hash_table_t* _ebpf_async_tracker_table = NULL;

_Must_inspect_result_ ebpf_result_t
ebpf_async_initiate()
{
    EBPF_LOG_ENTRY();

    const ebpf_hash_table_creation_options_t options = {
        .key_size = sizeof(ebpf_handle_t),
        .value_size = sizeof(ebpf_async_tracker_t),
    };

    EBPF_RETURN_RESULT(ebpf_hash_table_create(&_ebpf_async_tracker_table, &options));
}

void
ebpf_async_terminate()
{
    EBPF_LOG_ENTRY();
    ebpf_assert(!_ebpf_async_tracker_table || ebpf_hash_table_key_count(_ebpf_async_tracker_table) == 0);
    ebpf_hash_table_destroy(_ebpf_async_tracker_table);
    _ebpf_async_tracker_table = NULL;
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_async_set_completion_callback(
    _In_ const void* context, _In_ void (*on_complete)(_Inout_ void*, size_t, ebpf_result_t))
{
    EBPF_LOG_ENTRY();
    ebpf_async_tracker_t tracker = {on_complete};

    uint8_t* key = (uint8_t*)&context;
    EBPF_RETURN_RESULT(
        ebpf_hash_table_update(_ebpf_async_tracker_table, key, (uint8_t*)(&tracker), EBPF_HASH_TABLE_OPERATION_INSERT));
}

static ebpf_async_tracker_t*
_tracker_from_context(_In_ const void* context)
{
    uint8_t* key = (uint8_t*)&context;
    ebpf_async_tracker_t* tracker = NULL;
    ebpf_result_t result = ebpf_hash_table_find(_ebpf_async_tracker_table, key, (uint8_t**)&tracker);
    if (result != EBPF_SUCCESS) {
        return NULL;
    } else {
        return tracker;
    }
}

static ebpf_result_t
_remove_tracker(_In_ const void* context)
{
    uint8_t* key = (uint8_t*)&context;
    return ebpf_hash_table_delete(_ebpf_async_tracker_table, key);
}

_Must_inspect_result_ ebpf_result_t
ebpf_async_set_cancel_callback(
    _In_ const void* context,
    _Inout_opt_ void* cancellation_context,
    _In_ void (*on_cancel)(_Inout_opt_ void* cancellation_context))
{
    EBPF_LOG_ENTRY();
    ebpf_async_tracker_t* tracker = _tracker_from_context(context);
    if (!tracker) {
        return EBPF_INVALID_ARGUMENT;
    }
    tracker->cancellation_context = cancellation_context;
    tracker->on_cancel = on_cancel;
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

bool
ebpf_async_cancel(_Inout_ void* context)
{
    EBPF_LOG_ENTRY();
    ebpf_async_tracker_t* tracker = _tracker_from_context(context);
    if (!tracker) {
        EBPF_RETURN_BOOL(false);
    }

    void* cancellation_context = tracker->cancellation_context;
    void (*on_cancellation)(_Inout_ void* context) = tracker->on_cancel;
    if (on_cancellation) {
        on_cancellation(cancellation_context);
    }

    EBPF_RETURN_BOOL(true);
}

void
ebpf_async_complete(_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result)
{
    EBPF_LOG_ENTRY();
    ebpf_async_tracker_t* tracker = _tracker_from_context(context);
    if (!tracker) {
        ebpf_assert(!"Async action was double completed");
        EBPF_RETURN_VOID();
    }
    void (*on_complete)(_Inout_ void*, size_t, ebpf_result_t) = tracker->on_complete;
    if (_remove_tracker(context) != EBPF_SUCCESS) {
        ebpf_assert(!"Async action was double completed");
        EBPF_RETURN_VOID();
        return;
    }
    if (on_complete) {
        on_complete(context, output_buffer_length, result);
    }
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_async_reset_completion_callback(_In_ const void* context)
{
    return _remove_tracker(context);
}