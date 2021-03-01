/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#pragma once


// XDP like hook
typedef struct _xdp_md {
    uint64_t                      data;                 /*     0     8 */
    uint64_t                      data_end;             /*     8     8 */
    uint64_t                      data_meta;            /*     16    8 */

    /* size: 12, cachelines: 1, members: 3 */
    /* last cacheline: 12 bytes */
} xdp_md_t;

typedef DWORD(__stdcall* xdp_hook_function) (PVOID);

typedef enum _xdp_action
{
    XDP_PASS = 1,
    XDP_DROP = 2
} xdp_action_t;

// BIND hook
typedef struct _bind_md {
    uint64_t                      sock_address_start;
    uint64_t                      sock_address_end;
    uint64_t                      app_id_start;
    uint64_t                      app_id_end;
    uint64_t                      process_id;
    uint8_t                       operation;
    uint8_t                       protocol;
} bind_md_t;

typedef enum _bind_operation
{
    BIND_OPERATION_BIND,          // Entry to bind
    BIND_OPERATION_POST_BIND,     // After port allocation
    BIND_OPERATION_UNBIND,        // Release port
} bind_operation_t;

typedef enum _bind_action
{
    BIND_PERMIT,
    BIND_DENY,
    BIND_REDIRECT,
} bind_action_t;

typedef DWORD(__stdcall* bind_hook_function) (PVOID);

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

xdp_action_t
ebpf_core_invoke_xdp_hook(
    _In_ void* buffer,
    _In_ uint32_t buffer_length);

bind_action_t
ebpf_core_invoke_bind_hook(
    _In_ struct sockaddr* sockaddr,
    _In_ uint32_t sockaddr_length,
    _In_ uint8_t* app_id,
    _In_ uint32_t app_id_length,
    _In_ uint64_t process_id,
    _In_ bind_operation_t operation,
    _In_ uint8_t protocol
    );

