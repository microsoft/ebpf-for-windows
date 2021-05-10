/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "pch.h"
#include "rpc_interface_s.c"
#include <malloc.h>

#pragma comment(lib, "Rpcrt4.lib")

#define RPC_SERVER_ENDPOINT L"\\pipe\\ebpf_service"
static bool _rpc_server_initialized = false;

DWORD
initialize_rpc_server()
{
    RPC_STATUS status;
    const WCHAR* protocol_sequence = L"ncacn_np";
    unsigned char* security = nullptr;
    const WCHAR* endpoint = RPC_SERVER_ENDPOINT;
    unsigned int minimum_calls = 1;
    unsigned int dont_wait = true;
    bool registered = false;

    status = RpcServerUseProtseqEp(
        (RPC_WSTR)protocol_sequence, RPC_C_LISTEN_MAX_CALLS_DEFAULT, (RPC_WSTR)endpoint, security);
    if (status != RPC_S_OK) {
        goto Exit;
    }

    status = RpcServerRegisterIf(ebpf_service_interface_v1_0_s_ifspec, nullptr, nullptr);
    if (status != RPC_S_OK) {
        goto Exit;
    }
    registered = true;

    status = RpcServerListen(minimum_calls, RPC_C_LISTEN_MAX_CALLS_DEFAULT, dont_wait);

    if (status == RPC_S_OK) {
        _rpc_server_initialized = true;
    }
Exit:
    if (status != RPC_S_OK) {
        if (registered) {
            RpcServerUnregisterIf(nullptr, nullptr, true);
        }
    }
    return status;
}

void
shutdown_rpc_server()
{
    if (!_rpc_server_initialized) {
        return;
    }
    RPC_STATUS status;

    status = RpcMgmtStopServerListening(nullptr);
    if (status != RPC_S_OK) {
        // TODO: Add a trace that something happened.
        return;
    }

    status = RpcServerUnregisterIf(nullptr, nullptr, true);
    if (status != RPC_S_OK) {
        // TODO: Add a trace that something happened.
        return;
    }

    return;
}

/******************************************************/
/*         MIDL allocate and free                     */
/******************************************************/
_Must_inspect_result_ _Ret_maybenull_ _Post_writable_byte_size_(size) void* __RPC_USER
    MIDL_user_allocate(_In_ size_t size)
{
    return (malloc(size));
}

void __RPC_USER
MIDL_user_free(_Pre_maybenull_ _Post_invalid_ void* ptr)
{
    free(ptr);
}
