// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <malloc.h>
#include "rpc_interface_s.c"
#include "svc_common.h"

#pragma comment(lib, "Rpcrt4.lib")

#define ANNOTATION L"ebpfsvc rpc server"
#define EBPF_SERVICE_INTERFACE_HANDLE ebpf_server_ebpf_service_interface_v1_0_s_ifspec

static const WCHAR* _protocol_sequence = L"ncalrpc";
static bool _rpc_server_initialized = false;

DWORD
initialize_rpc_server()
{
    RPC_STATUS status;
    bool registered = false;
    RPC_BINDING_VECTOR* binding_vector = nullptr;

    status = RpcServerUseProtseq((RPC_WSTR)_protocol_sequence, RPC_C_PROTSEQ_MAX_REQS_DEFAULT, nullptr);
    if (status != RPC_S_OK) {
        goto Exit;
    }

    status = RpcServerRegisterIfEx(
        EBPF_SERVICE_INTERFACE_HANDLE, nullptr, nullptr, RPC_IF_AUTOLISTEN, RPC_C_LISTEN_MAX_CALLS_DEFAULT, nullptr);
    if (status != RPC_S_OK) {
        goto Exit;
    }
    registered = true;

    status = RpcServerInqBindings(&binding_vector);
    if (status != RPC_S_OK) {
        goto Exit;
    }

    status = RpcEpRegister(EBPF_SERVICE_INTERFACE_HANDLE, binding_vector, NULL, (RPC_WSTR)ANNOTATION);

    if (status == RPC_S_OK) {
        _rpc_server_initialized = true;
    }

Exit:
    if (binding_vector != nullptr) {
        RpcBindingVectorFree(&binding_vector);
    }
    if (status != RPC_S_OK) {
        if (registered) {
            RPC_STATUS unregister_status = RpcServerUnregisterIf(nullptr, nullptr, true);
            if (unregister_status != RPC_S_OK) {
                // TODO: Add a trace that something happened.
            }
        }
    }
    return status;
}

void
shutdown_rpc_server()
{
    RPC_STATUS status;
    RPC_BINDING_VECTOR* binding_vector = nullptr;

    if (!_rpc_server_initialized) {
        return;
    }

    status = RpcServerInqBindings(&binding_vector);
    if (status != RPC_S_OK) {
        goto Exit;
    }

    status = RpcEpUnregister(EBPF_SERVICE_INTERFACE_HANDLE, binding_vector, nullptr);
    if (status != RPC_S_OK) {
        goto Exit;
    }

    status = RpcServerUnregisterIf(EBPF_SERVICE_INTERFACE_HANDLE, nullptr, true);
    if (status != RPC_S_OK) {
        // TODO: Add a trace that something happened.
        goto Exit;
    }

Exit:
    if (binding_vector != nullptr) {
        RpcBindingVectorFree(&binding_vector);
    }
    return;
}
