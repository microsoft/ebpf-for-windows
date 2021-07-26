// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <limits.h>
#include "ebpf_platform.h"

#include "ebpf_program_types_c.c"

ebpf_result_t
ebpf_program_info_encode(
    _In_ const ebpf_program_info_t* program_info,
    _Outptr_result_bytebuffer_(*buffer_size) uint8_t** buffer,
    _Out_ unsigned long* buffer_size)
{
    handle_t handle = NULL;
    ebpf_program_info_pointer_t local_program_info = (ebpf_program_info_t*)program_info;
    *buffer_size = 0;
    RPC_STATUS status = MesEncodeDynBufferHandleCreate((char**)buffer, buffer_size, &handle);
    if (status != RPC_S_OK)
        return EBPF_NO_MEMORY;

    RpcTryExcept { ebpf_program_info_pointer_t_Encode(handle, &local_program_info); }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode())) { status = RpcExceptionCode(); }
    RpcEndExcept;

    if (handle)
        MesHandleFree(handle);
    return status == RPC_S_OK ? EBPF_SUCCESS : EBPF_INVALID_ARGUMENT;
}

ebpf_result_t
ebpf_program_info_decode(
    _Outptr_ ebpf_program_info_t** program_info,
    _In_ _Readable_bytes_(buffer_size) const uint8_t* buffer,
    size_t buffer_size)
{
    ebpf_result_t return_value;
    handle_t handle = NULL;
    ebpf_program_info_pointer_t local_program_info = NULL;
    uint8_t* local_buffer = NULL;

    if (buffer_size > ULONG_MAX) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    local_buffer = ebpf_allocate(buffer_size);
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

    RpcTryExcept { ebpf_program_info_pointer_t_Decode(handle, &local_program_info); }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode())) { status = RpcExceptionCode(); }
    RpcEndExcept;

    if (status != RPC_S_OK) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    *program_info = local_program_info;
    return_value = EBPF_SUCCESS;

Done:
    if (handle)
        MesHandleFree(handle);
    ebpf_free(local_buffer);

    return return_value;
}

// The _In_ on size is necessary to avoid inconsistent annotation warnings.
_Must_inspect_result_ _Ret_maybenull_ _Post_writable_byte_size_(size) void* __RPC_USER
    MIDL_user_allocate(_In_ size_t size)
{
    return ebpf_allocate(size);
}

void __RPC_USER
MIDL_user_free(_Pre_maybenull_ _Post_invalid_ void* p)
{
    ebpf_free(p);
}
