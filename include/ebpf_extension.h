// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_result.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"

typedef ebpf_result_t (*ebpf_program_invoke_function_t)(
    _In_ const void* extension_client_binding_context, _Inout_ void* program_context, _Out_ uint32_t* result);

typedef ebpf_result_t (*ebpf_program_batch_begin_invoke_function_t)(
    _In_ const void* extension_client_binding_context, size_t state_size, _Out_writes_(state_size) void* state);

typedef ebpf_result_t (*ebpf_program_batch_invoke_function_t)(
    _In_ const void* extension_client_binding_context,
    _Inout_ void* program_context,
    _Out_ uint32_t* result,
    _In_ const void* state);

typedef ebpf_result_t (*ebpf_program_batch_end_invoke_function_t)(_In_ const void* extension_client_binding_context);

typedef ebpf_result_t (*_ebpf_extension_dispatch_function)();

typedef struct _ebpf_extension_dispatch_table
{
    uint16_t version; ///< Version of the dispatch table.
    uint16_t count;   ///< Number of entries in the dispatch table.
    _Field_size_(count) _ebpf_extension_dispatch_function function[1];
} ebpf_extension_dispatch_table_t;

typedef struct _ebpf_extension_data
{
    uint16_t version;
    size_t size;
    void* data;
} ebpf_extension_data_t;

typedef struct _ebpf_attach_provider_data
{
    ebpf_program_type_t supported_program_type;
    bpf_attach_type_t bpf_attach_type;
    enum bpf_link_type link_type;
} ebpf_attach_provider_data_t;

/***
 * The state of the execution context when the eBPF program was invoked.
 * This is used to cache state that won't change during the execution of
 * the eBPF program and is expensive to query.
 */
typedef struct _ebpf_execution_context_state
{
    struct _ebpf_epoch_state* epoch_state;
    union
    {
        uint64_t thread;
        uint32_t cpu;
    } id;
    uint8_t current_irql;
} ebpf_execution_context_state_t;

#define EBPF_ATTACH_CLIENT_DATA_VERSION 0
#define EBPF_ATTACH_PROVIDER_DATA_VERSION 1
#define EBPF_MAX_GENERAL_HELPER_FUNCTION 0xFFFF
