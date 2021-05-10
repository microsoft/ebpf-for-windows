/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

typedef struct _MIDL_TYPE_PICKLING_INFO
{
    unsigned long Version;
    unsigned long Flags;
    UINT_PTR Reserved[3];
} MIDL_TYPE_PICKLING_INFO, *PMIDL_TYPE_PICKLING_INFO;

size_t RPC_ENTRY
NdrMesTypeAlignSize2(
    handle_t handle,
    const MIDL_TYPE_PICKLING_INFO* pickling_info,
    const MIDL_STUB_DESC* stub_desc,
    PFORMAT_STRING format_string,
    const void* object);

void RPC_ENTRY
NdrMesTypeEncode2(
    handle_t handle,
    const MIDL_TYPE_PICKLING_INFO* pickling_info,
    const MIDL_STUB_DESC* stub_desc,
    PFORMAT_STRING format_string,
    const void* object);

void RPC_ENTRY
NdrMesTypeDecode2(
    handle_t handle,
    const MIDL_TYPE_PICKLING_INFO* pickling_info,
    const MIDL_STUB_DESC* stub_desc,
    PFORMAT_STRING format_string,
    void* object);

void RPC_ENTRY
NdrMesTypeFree2(
    handle_t handle,
    const MIDL_TYPE_PICKLING_INFO* pickling_info,
    const MIDL_STUB_DESC* stub_desc,
    PFORMAT_STRING format_string,
    void* object);

RPC_STATUS RPC_ENTRY
MesEncodeDynBufferHandleCreate(
    _Outptr_result_bytebuffer_(*encoded_size) char** buffer, _Out_ unsigned long* encoded_size, _Out_ handle_t* handle);

RPC_STATUS RPC_ENTRY
MesHandleFree(handle_t handle);

RPC_STATUS RPC_ENTRY
MesDecodeBufferHandleCreate(
    _In_reads_bytes_(buffer_size) char* buffer, _In_ unsigned long buffer_size, _Out_ handle_t* handle);
