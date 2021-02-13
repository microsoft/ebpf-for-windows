/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#pragma once


// XDP like hook
typedef struct xdp_md_ {
    UINT64                      data;                 /*     0     8 */
    UINT64                      data_end;             /*     8     8 */
    UINT64                      data_meta;            /*     16    8 */

    /* size: 12, cachelines: 1, members: 3 */
    /* last cacheline: 12 bytes */
} xdp_md;

typedef DWORD(__stdcall* XDP_HOOK) (PVOID);

typedef enum xdp_action_
{
    XDP_PASS = 1,
    XDP_DROP = 2
} xdp_action;

typedef enum ebpf_map_type_
{
    ebpf_map_array = 2
} ebpf_map_type;

typedef enum ebpf_helper_function_
{
    ebpf_lookup_element = 1,
    ebpf_update_element = 2,
    ebpf_delete_element = 3,
    ebpf_invalid
} ebpf_helper_function;

typedef enum ebpf_hook_point_
{
    ebpf_hook_none = 0,
    ebpf_hook_xdp = 1
} ebpf_hook_point;

NTSTATUS EbpfCoreInitialize();
void EbpfCoreTerminate();

NTSTATUS
EbpfCoreProtocolAttachCode(
    _In_ struct EbpfOpAttachDetachRequest* request,
    _Inout_ void* reply);

NTSTATUS
EbpfCoreProtocolDetachCode(
    _In_ struct EbpfOpAttachDetachRequest* request,
    _Inout_ void* reply);

NTSTATUS
EbpfCoreProtocolUnloadCode(
    _In_ struct EbpfOpUnloadRequest* request,
    _Inout_ void* reply);

NTSTATUS
EbpfCoreProtocolLoadCode(
    _In_ struct EbpfOpLoadRequest* inputRequest,
    _Inout_ struct EbpfOpLoadReply* loadReply);

NTSTATUS EbpfCoreProtocolResolveHelper(
    _In_ struct EbpfOpResolveHelperRequest* request,
    _Out_ struct EbpfOpResolveHelperReply* reply);

NTSTATUS EbpfCoreProtocolResolveMap(
    _In_ struct EbpfOpResolveMapRequest* request,
    _Out_ struct EbpfOpResolveMapReply* reply);

NTSTATUS EbpfCoreProtocolCreateMap(
    _In_ struct EbpfOpCreateMapRequest* request,
    _Inout_ struct EbpfOpCreateMapReply* reply);

NTSTATUS EbpfCoreProtocolMapLookupElement(
    _In_ struct EbpfOpMapLookupElementRequest* request,
    _Inout_ struct EbpfOpMapLookupElementReply* reply);

NTSTATUS EbpfCoreProtocolMapUpdateElement(
    _In_ struct EpfOpMapUpdateElementRequest* request,
    _Inout_ void* reply);

NTSTATUS EbpfCoreProtocolMapDeleteElement(
    _In_ struct EbpfOpMapDeleteElementRequest* request,
    _Inout_ void* reply);

xdp_action
EbpfCoreInvokeXdpHook(
    _In_ void* buffer,
    _In_ uint32_t buffer_length
    );


