/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include <limits.h>
#include "ebpf_platform.h"

#include "ebpf_program_types_c.c"

ebpf_result_t
ebpf_program_information_encode(
    const ebpf_program_information_t* program_information, uint8_t** buffer, unsigned long* buffer_size)
{
    handle_t handle = NULL;
    ebpf_program_information_pointer_t local_program_information = (ebpf_program_information_t*)program_information;
    RPC_STATUS status = MesEncodeDynBufferHandleCreate((char**)buffer, buffer_size, &handle);
    if (status != RPC_S_OK)
        return EBPF_NO_MEMORY;

    RpcTryExcept { ebpf_program_information_pointer_t_Encode(handle, &local_program_information); }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode())) { status = RpcExceptionCode(); }
    RpcEndExcept;

    if (handle)
        MesHandleFree(handle);
    return status == RPC_S_OK ? EBPF_SUCCESS : EBPF_INVALID_ARGUMENT;
}

ebpf_result_t
ebpf_program_information_decode(
    ebpf_program_information_t** program_information, const uint8_t* buffer, size_t buffer_size)
{
    ebpf_result_t return_value;
    handle_t handle = NULL;
    ebpf_program_information_pointer_t local_program_information = NULL;
    uint8_t* local_buffer = NULL;

    if (buffer_size > ULONG_MAX) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    local_buffer = ebpf_allocate(buffer_size, EBPF_MEMORY_NO_EXECUTE);
    if (!local_buffer) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    memcpy(local_buffer, buffer, buffer_size);

    RPC_STATUS status = MesDecodeBufferHandleCreate((char*)local_buffer, (unsigned long)buffer_size, &handle);
    if (status != RPC_S_OK) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    RpcTryExcept { ebpf_program_information_pointer_t_Decode(handle, &local_program_information); }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode())) { status = RpcExceptionCode(); }
    RpcEndExcept;

    if (status != RPC_S_OK) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    *program_information = local_program_information;

Done:
    if (handle)
        MesHandleFree(handle);
    ebpf_free(local_buffer);

    return EBPF_SUCCESS;
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
