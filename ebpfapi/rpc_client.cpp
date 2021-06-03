// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <ctype.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "ebpf_api.h"
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#undef VOID
#pragma warning(pop)
#include "ebpf_windows.h"
#include "rpc_interface_c.c"

#pragma comment(lib, "Rpcrt4.lib")

static RPC_WSTR _string_binding = nullptr;
static const WCHAR* _protocol_sequence = L"ncalrpc";

#define RPC_SERVER_ENDPOINT L"ebpfsvc rpc server"

int
ebpf_rpc_verify_program(ebpf_program_verify_info* info, const char** logs, uint32_t* logs_size)
{
    int result;

    RpcTryExcept { result = (int)ebpf_client_verify_program(info, logs_size, const_cast<char**>(logs)); }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode()))
    {
        result = RpcExceptionCode();
    }
    RpcEndExcept

    return result;
}

int
ebpf_rpc_load_program(ebpf_program_load_info* info, const char** logs, uint32_t* logs_size)
{
    int result;

    RpcTryExcept { result = (int)ebpf_client_verify_and_load_program(info, logs_size, const_cast<char**>(logs)); }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode()))
    {
        result = RpcExceptionCode();
    }
    RpcEndExcept

        return result;
}

RPC_STATUS
initialize_rpc_binding()
{
    RPC_STATUS status;
    RPC_WSTR uuid = nullptr;
    const WCHAR* network_address = nullptr;
    RPC_WSTR options = nullptr;

    status = RpcStringBindingCompose(
        uuid,
        (RPC_WSTR)_protocol_sequence,
        (RPC_WSTR)network_address,
        (RPC_WSTR)RPC_SERVER_ENDPOINT,
        options,
        &_string_binding);

    if (status != RPC_S_OK) {
        return status;
    }

    return RpcBindingFromStringBinding(_string_binding, &ebpf_service_interface_handle);
}

RPC_STATUS
clean_up_rpc_binding()
{
    RPC_STATUS status = RpcStringFree(&_string_binding);
    if (status != RPC_S_OK) {
        printf("RpcStringFree failed with error %d\n", status);
    }

    status = RpcBindingFree(&ebpf_service_interface_handle);
    if (status != RPC_S_OK) {
        printf("RpcBindingFree failed with error %d\n", status);
    }

    return status;
}
