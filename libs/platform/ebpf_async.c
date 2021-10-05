// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_async.h"
#include "ebpf_epoch.h"

typedef struct _ebpf_async_tracker
{
    void (*on_complete)(_In_ void* context, ebpf_result_t result);
    void* cancellation_context;
    void (*on_cancel)(_In_ void* context);
} ebpf_async_tracker_t;

static ebpf_hash_table_t* _ebpf_async_tracker_table = NULL;

static const size_t _ebpf_async_tracker_table_bucket_count = 64;

ebpf_result_t
ebpf_async_initiate()
{
    return ebpf_hash_table_create(
        &_ebpf_async_tracker_table,
        ebpf_epoch_allocate,
        ebpf_epoch_free,
        sizeof(void*),
        sizeof(ebpf_async_tracker_t),
        _ebpf_async_tracker_table_bucket_count,
        NULL);
}

void
ebpf_async_terminate()
{
    ebpf_assert(ebpf_hash_table_key_count(_ebpf_async_tracker_table) == 0);
    ebpf_hash_table_destroy(_ebpf_async_tracker_table);
    _ebpf_async_tracker_table = NULL;
}

ebpf_result_t
ebpf_async_set_completion_callback(
    _In_ void* context, _In_ void (*on_complete)(_In_ void* context, ebpf_result_t result))
{
    ebpf_async_tracker_t tracker = {on_complete};

    uint8_t* key = (uint8_t*)&context;
    return ebpf_hash_table_update(
        _ebpf_async_tracker_table, key, (uint8_t*)(&tracker), EBPF_HASH_TABLE_OPERATION_INSERT);
}

static ebpf_async_tracker_t*
_tracker_from_context(_In_ void* context)
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

static bool
_remove_tracker(_In_ void* context)
{
    uint8_t* key = (uint8_t*)&context;
    return ebpf_hash_table_delete(_ebpf_async_tracker_table, key) == EBPF_SUCCESS;
}

ebpf_result_t
ebpf_async_set_cancel_callback(
    _In_ void* context, _In_ void* cancellation_context, _In_ void (*on_cancel)(_In_ void* cancellation_context))
{
    ebpf_async_tracker_t* tracker = _tracker_from_context(context);
    if (!tracker) {
        return EBPF_INVALID_ARGUMENT;
    }
    tracker->cancellation_context = cancellation_context;
    tracker->on_cancel = on_cancel;
    return EBPF_SUCCESS;
}

bool
ebpf_async_cancel(_In_ void* context)
{
    ebpf_async_tracker_t* tracker = _tracker_from_context(context);
    if (!tracker) {
        return false;
    }
    void* cancellation_context = tracker->cancellation_context;
    void (*on_cancellation)(_In_ void* context) = tracker->on_cancel;
    if (on_cancellation)
        on_cancellation(cancellation_context);
    return true;
}

bool
ebpf_async_complete(_In_ void* context, ebpf_result_t result)
{
    ebpf_async_tracker_t* tracker = _tracker_from_context(context);
    if (!tracker) {
        return false;
    }
    void (*on_complete)(_In_ void* context, ebpf_result_t result) = tracker->on_complete;
    if (_remove_tracker(context)) {
        if (on_complete)
            on_complete(context, result);
        return true;
    } else {
        return false;
    }
}
