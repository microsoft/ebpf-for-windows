/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_platform.h"

#include "ebpf_program_types_c.c"

ebpf_error_code_t
ebpf_program_information_encode(
    ebpf_program_information_t* program_information, uint8_t** buffer, unsigned long* buffer_size)
{
    handle_t handle = NULL;
    ebpf_program_information_pointer_t local_program_information = program_information;
    RPC_STATUS status = MesEncodeDynBufferHandleCreate((char**)buffer, buffer_size, &handle);
    if (status != RPC_S_OK)
        return EBPF_ERROR_OUT_OF_RESOURCES;

    RpcTryExcept { ebpf_program_information_pointer_t_Encode(handle, &local_program_information); }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode())) { status = RpcExceptionCode(); }
    RpcEndExcept;

    if (handle)
        MesHandleFree(handle);
    return status == RPC_S_OK ? EBPF_ERROR_SUCCESS : EBPF_ERROR_INVALID_PARAMETER;
}

ebpf_error_code_t
ebpf_program_information_decode(
    ebpf_program_information_t** program_information, uint8_t* buffer, unsigned long buffer_size)
{
    handle_t handle = NULL;
    ebpf_program_information_pointer_t local_program_information = NULL;

    RPC_STATUS status = MesDecodeBufferHandleCreate((char*)buffer, buffer_size, &handle);
    if (status != RPC_S_OK)
        return EBPF_ERROR_OUT_OF_RESOURCES;

    RpcTryExcept { ebpf_program_information_pointer_t_Decode(handle, &local_program_information); }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode())) { status = RpcExceptionCode(); }
    RpcEndExcept;

    if (handle)
        MesHandleFree(handle);
    if (status != RPC_S_OK)
        return EBPF_ERROR_INVALID_PARAMETER;

    *program_information = local_program_information;

    return EBPF_ERROR_SUCCESS;
}

void* __RPC_USER
MIDL_user_allocate(size_t size)
{
    return ebpf_allocate(size, EBPF_MEMORY_NO_EXECUTE);
}

void __RPC_USER
MIDL_user_free(void* p)
{
    ebpf_free(p);
}
