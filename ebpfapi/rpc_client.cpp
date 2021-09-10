// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <ctype.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "ebpf_api.h"
#include "rpc_interface_c.c"

#pragma comment(lib, "Rpcrt4.lib")

static RPC_WSTR _string_binding = nullptr;
static const WCHAR* _protocol_sequence = L"ncalrpc";
static bool _binding_initialized = false;

ebpf_result_t
ebpf_rpc_verify_program(
    _In_ ebpf_program_verify_info* info,
    _Outptr_result_maybenull_z_ const char** logs,
    _Out_ uint32_t* logs_size) noexcept
{
    ebpf_result_t result;

    RpcTryExcept { result = ebpf_client_verify_program(info, logs_size, const_cast<char**>(logs)); }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode()))
    {
        // TODO: (Issue# 247) Add tracing for the RpcExceptionCode() that is returned.
        result = EBPF_RPC_EXCEPTION;
    }
    RpcEndExcept

        return result;
}

ebpf_result_t
ebpf_rpc_load_program(
    _In_ ebpf_program_load_info* info,
    _Outptr_result_maybenull_z_ const char** logs,
    _Inout_ uint32_t* logs_size) noexcept
{
    ebpf_result_t result;

    RpcTryExcept { result = ebpf_client_verify_and_load_program(info, logs_size, const_cast<char**>(logs)); }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode()))
    {
        // TODO: (Issue# 247) Add tracing for the RpcExceptionCode() that is returned.
        result = EBPF_RPC_EXCEPTION;
    }
    RpcEndExcept

        return result;
}

RPC_STATUS
initialize_rpc_binding()
{
    RPC_STATUS status =
        RpcStringBindingCompose(nullptr, (RPC_WSTR)_protocol_sequence, nullptr, nullptr, nullptr, &_string_binding);

    if (status != RPC_S_OK) {
        return status;
    }

    status = RpcBindingFromStringBinding(_string_binding, &ebpf_service_interface_handle);
    if (status == RPC_S_OK) {
        _binding_initialized = true;
    }

    return status;
}

RPC_STATUS
clean_up_rpc_binding()
{
    RPC_STATUS status = RpcStringFree(&_string_binding);
    if (status != RPC_S_OK) {
        printf("RpcStringFree failed with error %d\n", status);
    }

    if (_binding_initialized) {
        status = RpcBindingFree(&ebpf_service_interface_handle);
        if (status != RPC_S_OK) {
            printf("RpcBindingFree failed with error %d\n", status);
        }
    }

    return status;
}
