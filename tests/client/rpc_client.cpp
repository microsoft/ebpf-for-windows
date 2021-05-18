// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "header.h"
#include "rpc_interface_c.c"

#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#undef VOID
#include "ebpf_verifier.hpp"
#pragma warning(pop)
#include "ebpf_windows.h"
#include "ebpf_api.h"

#pragma comment(lib, "Rpcrt4.lib")

static RPC_WSTR _string_binding = nullptr;
static const WCHAR* _protocol_sequence = L"ncacn_np";

#define RPC_SERVER_ENDPOINT L"\\pipe\\ebpf_service"

int
ebpf_rpc_verify_program(ebpf_program_verify_info* info, unsigned char** logs, uint32_t* logs_size)
{
    unsigned long ulCode;
    int retCode;

    RpcTryExcept
    {
        retCode = (int)ebpf_verify_program(info, logs_size, logs);
    }
    RpcExcept(1)
    {
        ulCode = RpcExceptionCode();
        printf("ebpf_rpc_verify_program: runtime reported exception 0x%lx = %ld\n", ulCode, ulCode);
        retCode = (int)EBPF_FAILED;
    }
    RpcEndExcept

    printf("ebpf_rpc_verify_program: got return code %d from the server\n\n", retCode);

    return retCode;
}

RPC_STATUS
initialize_rpc_binding()
{
    RPC_STATUS status;
    RPC_WSTR pszUuid = NULL;
    const WCHAR* pszNetworkAddress = nullptr; //  L"\\\\10.216.117.143";
    RPC_WSTR pszOptions = NULL;

    status = RpcStringBindingCompose(
        pszUuid,
        (RPC_WSTR)_protocol_sequence,
        (RPC_WSTR)pszNetworkAddress,
        (RPC_WSTR)RPC_SERVER_ENDPOINT,
        pszOptions,
        &_string_binding);

    if (status != RPC_S_OK) {
        return status;
    }

    return RpcBindingFromStringBinding(_string_binding, &ebpf_service_interface_handle);
}

RPC_STATUS
cleanup_rpc_binding()
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
