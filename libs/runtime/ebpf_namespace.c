// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_namespace.h"

void
ebpf_namespace_state_initialize(_Out_ ebpf_namespace_state_t* state)
{
    memset(state, 0, sizeof(*state));
    ebpf_lock_create(&state->lock);
}

void
ebpf_namespace_state_close(_Inout_ ebpf_namespace_state_t* state)
{
    ebpf_lock_state_t lock_state = ebpf_lock_lock(&state->lock);
    state->closing = true;
    ebpf_lock_unlock(&state->lock, lock_state);
}

void
ebpf_namespace_state_destroy(_Inout_ ebpf_namespace_state_t* state)
{
    ebpf_lock_destroy(&state->lock);
}

ebpf_result_t
ebpf_namespace_state_capture(_Inout_ ebpf_namespace_state_t* state, _Out_ ebpf_request_context_t* context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t lock_state = ebpf_lock_lock(&state->lock);
    if (state->closing) {
        result = EBPF_INVALID_STATE;
    } else {
        const ebpf_request_context_t snapshot = {
            .namespace_id = state->namespace_id,
            .namespace_generation = state->generation,
            .namespace_target = state,
        };
        *context = snapshot;
    }
    ebpf_lock_unlock(&state->lock, lock_state);
    return result;
}

ebpf_result_t
ebpf_namespace_state_set(_Inout_ ebpf_namespace_state_t* state, _In_ const GUID* namespace_id)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t lock_state = ebpf_lock_lock(&state->lock);
    if (state->closing) {
        result = EBPF_INVALID_STATE;
    } else if (memcmp(&state->namespace_id, namespace_id, sizeof(*namespace_id)) != 0) {
        if (state->generation == UINT64_MAX) {
            result = EBPF_ARITHMETIC_OVERFLOW;
        } else {
            state->namespace_id = *namespace_id;
            state->generation++;
        }
    }
    ebpf_lock_unlock(&state->lock, lock_state);
    return result;
}
