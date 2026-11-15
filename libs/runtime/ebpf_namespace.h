// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

CXPLAT_EXTERN_C_BEGIN

typedef struct _ebpf_namespace_state
{
    ebpf_lock_t lock;
    GUID namespace_id;
    uint64_t generation;
    bool closing;
} ebpf_namespace_state_t;

typedef struct _ebpf_request_context
{
    GUID namespace_id;
    uint64_t namespace_generation;
    ebpf_namespace_state_t* namespace_target;
    struct _ebpf_core_object* referenced_object;
} ebpf_request_context_t;

void
ebpf_namespace_state_initialize(_Out_ ebpf_namespace_state_t* state);

void
ebpf_namespace_state_close(_Inout_ ebpf_namespace_state_t* state);

void
ebpf_namespace_state_destroy(_Inout_ ebpf_namespace_state_t* state);

_Must_inspect_result_ ebpf_result_t
ebpf_namespace_state_capture(_Inout_ ebpf_namespace_state_t* state, _Out_ ebpf_request_context_t* context);

_Must_inspect_result_ ebpf_result_t
ebpf_namespace_state_set(_Inout_ ebpf_namespace_state_t* state, _In_ const GUID* namespace_id);

CXPLAT_EXTERN_C_END
