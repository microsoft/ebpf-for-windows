// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_api.h"
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#undef VOID
#include "ebpf_verifier.hpp"
#pragma warning(pop)
#include "ebpf_windows.h"
#include "header.h"
#include "rpc_interface_c.c"

#pragma comment(lib, "Rpcrt4.lib")

static RPC_WSTR _string_binding = nullptr;
static const WCHAR* _protocol_sequence = L"ncacn_np";

#define RPC_SERVER_ENDPOINT L"\\pipe\\ebpf_service"

int
ebpf_rpc_verify_program(ebpf_program_verify_info* info, char** logs, uint32_t* logs_size)
{
    unsigned long code;
    int result;

    RpcTryExcept
    {
        result = (int)ebpf_verify_program(info, logs_size, logs);
    }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode()))
    {
        code = RpcExceptionCode();
        printf("ebpf_rpc_verify_program: runtime reported exception 0x%lx = %ld\n", code, code);
        result = (int)EBPF_FAILED;
    }
    RpcEndExcept

    printf("ebpf_rpc_verify_program: got return code %d from the server\n\n", result);

    return result;
}

RPC_STATUS
initialize_rpc_binding()
{
    RPC_STATUS status;
    RPC_WSTR uuid = NULL;
    const WCHAR* network_address = nullptr;
    RPC_WSTR options = NULL;

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
