/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#include "ebpf_handle.h"

typedef ebpf_object_t* ebpf_handle_entry_t;

// Simplified handle table implementation.
// TODO: Replace this with the real Windows object manager handle table code.

static ebpf_lock_t _ebpf_handle_table_lock = {0};
static _Requires_lock_held_(&_ebpf_handle_table_lock) ebpf_handle_entry_t _ebpf_handle_table[1024];

static bool _ebpf_handle_table_initiated = false;

ebpf_result_t
ebpf_handle_table_initiate()
{
    ebpf_lock_create(&_ebpf_handle_table_lock);
    memset(_ebpf_handle_table, 0, sizeof(_ebpf_handle_table));
    _ebpf_handle_table_initiated = true;
    return EBPF_SUCCESS;
}

void
ebpf_handle_table_terminate()
{
    ebpf_handle_t handle;
    if (!_ebpf_handle_table_initiated)
        return;

    for (handle = 0; handle < EBPF_COUNT_OF(_ebpf_handle_table); handle++) {
        ebpf_handle_close(handle);
    }
    _ebpf_handle_table_initiated = false;
}

ebpf_result_t
ebpf_handle_create(ebpf_handle_t* handle, ebpf_object_t* object)
{
    ebpf_handle_t new_handle;
    ebpf_result_t return_value;
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&_ebpf_handle_table_lock);
    for (new_handle = 1; new_handle < EBPF_COUNT_OF(_ebpf_handle_table); new_handle++) {
        if (_ebpf_handle_table[new_handle] == NULL)
            break;
    }
    if (new_handle == EBPF_COUNT_OF(_ebpf_handle_table)) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    *handle = new_handle;
    _ebpf_handle_table[new_handle] = object;
    ebpf_object_acquire_reference(_ebpf_handle_table[new_handle]);

    return_value = EBPF_SUCCESS;

Done:
    ebpf_lock_unlock(&_ebpf_handle_table_lock, state);

    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_handle_close(ebpf_handle_t handle)
{
    ebpf_lock_state_t state;
    ebpf_result_t return_value;
    state = ebpf_lock_lock(&_ebpf_handle_table_lock);
    if (_ebpf_handle_table[handle] != NULL) {
        ebpf_object_release_reference(_ebpf_handle_table[handle]);
        _ebpf_handle_table[handle] = NULL;
        return_value = EBPF_SUCCESS;
    } else
        return_value = EBPF_INVALID_OBJECT;
    ebpf_lock_unlock(&_ebpf_handle_table_lock, state);
    return return_value;
}

ebpf_result_t
ebpf_reference_object_by_handle(ebpf_handle_t handle, ebpf_object_type_t object_type, ebpf_object_t** object)
{
    ebpf_result_t return_value;
    ebpf_lock_state_t state;

    if (handle >= EBPF_COUNT_OF(_ebpf_handle_table))
        return EBPF_INVALID_OBJECT;

    state = ebpf_lock_lock(&_ebpf_handle_table_lock);
    if ((_ebpf_handle_table[handle] != NULL) &&
        ((_ebpf_handle_table[handle]->type == object_type) || (object_type == EBPF_OBJECT_UNKNOWN))) {
        ebpf_object_acquire_reference(_ebpf_handle_table[handle]);
        *object = _ebpf_handle_table[handle];
        return_value = EBPF_SUCCESS;
    } else
        return_value = EBPF_INVALID_OBJECT;

    ebpf_lock_unlock(&_ebpf_handle_table_lock, state);
    return return_value;
}

ebpf_result_t
ebpf_get_next_handle_by_type(ebpf_handle_t previous_handle, ebpf_object_type_t object_type, ebpf_handle_t* next_handle)
{
    ebpf_lock_state_t state;

    previous_handle++;

    if (previous_handle > EBPF_COUNT_OF(_ebpf_handle_table))
        return EBPF_INVALID_OBJECT;

    state = ebpf_lock_lock(&_ebpf_handle_table_lock);
    for (*next_handle = previous_handle; *next_handle < EBPF_COUNT_OF(_ebpf_handle_table); (*next_handle)++) {
        if (_ebpf_handle_table[*next_handle] != NULL && _ebpf_handle_table[*next_handle]->type == object_type) {
            break;
        }
    }
    if (*next_handle == EBPF_COUNT_OF(_ebpf_handle_table)) {
        *next_handle = UINT64_MAX;
    }
    ebpf_lock_unlock(&_ebpf_handle_table_lock, state);

    return EBPF_SUCCESS;
}
