/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#pragma once

typedef enum _ebpf_helper_function
{
    EBPF_LOOKUP_ELEMENT = 1,
    EBPF_UPDATE_ELEMENT = 2,
    EBPF_DELETE_ELEMENT = 3,
    EBPF_INVALID
} ebpf_helper_function_t;

typedef enum _ebpf_hook_point
{
    EBPF_HOOK_NONE = 0,
    EBPF_HOOK_XDP = 1,
    EBPF_HOOK_BIND = 2,
} ebpf_hook_point_t;

typedef uint32_t(__stdcall* ebpf_hook_function) (PVOID);

typedef enum
{
    ebpfPoolTag = 'fpbe'
} EBPF_POOL_TAG;

NTSTATUS ebpf_core_initialize();
void ebpf_core_terminate();

NTSTATUS
ebpf_core_protocol_attach_code(
    _In_ const struct _ebpf_operation_attach_detach_request* request,
    _Inout_ void* reply);

NTSTATUS
ebpf_core_protocol_detach_code(
    _In_ const struct _ebpf_operation_attach_detach_request* request,
    _Inout_ void* reply);

NTSTATUS
ebpf_core_protocol_unload_code(
    _In_ const struct _ebpf_operation_unload_code_request* request,
    _Inout_ void* reply);

NTSTATUS
ebpf_core_protocol_load_code(
    _In_ const struct _ebpf_operation_load_code_request* inputRequest,
    _Inout_ struct _ebpf_operation_load_code_reply* loadReply);

NTSTATUS
ebpf_core_protocol_resolve_helper(
    _In_ const struct _ebpf_operation_resolve_helper_request* request,
    _Out_ struct _ebpf_operation_resolve_helper_reply* reply);

NTSTATUS
ebpf_core_protocol_resolve_map(
    _In_ const struct _ebpf_operation_resolve_map_request* request,
    _Out_ struct _ebpf_operation_resolve_map_reply* reply);

NTSTATUS
ebpf_core_protocol_create_map(
    _In_ const struct _ebpf_operation_create_map_request* request,
    _Inout_ struct _ebpf_operation_create_map_reply* reply);

NTSTATUS
ebpf_core_protocol_map_lookup_element(
    _In_ const struct _ebpf_operation_map_lookup_element_request* request,
    _Inout_ struct _ebpf_operation_map_lookup_element_reply* reply);

NTSTATUS
ebpf_core_protocol_map_update_element(
    _In_ const struct _ebpf_operation_map_update_element_request* request,
    _Inout_ void* reply);

NTSTATUS
ebpf_core_protocol_map_delete_element(
    _In_ const struct _ebpf_operation_map_delete_element_request* request,
    _Inout_ void* reply);

NTSTATUS
ebpf_core_protocol_enumerate_maps(
    _In_ const struct _ebpf_operation_enumerate_maps_request* request,
    _Inout_ struct _ebpf_operation_enumerate_maps_reply* reply);

NTSTATUS
ebpf_core_protocol_query_map_definition(
    _In_ const struct _ebpf_operation_query_map_definition_request* request,
    _Inout_ struct _ebpf_operation_query_map_definition_reply* reply);

NTSTATUS ebpf_core_invoke_hook(
    _In_ ebpf_hook_point_t hook_point,
    _Inout_ void* context,
    _Out_ uint32_t* result
);

