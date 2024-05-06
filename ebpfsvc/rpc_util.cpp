// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "svc_common.h"

#include <winsock2.h>
#include <windows.h>
#include <malloc.h>
#include <sddl.h>

#include "rpc_interface_s.c"

#pragma comment(lib, "Rpcrt4.lib")

#define ANNOTATION L"ebpfsvc rpc server"
#define EBPF_SERVICE_INTERFACE_HANDLE ebpf_server_ebpf_service_interface_v1_0_s_ifspec
#define MAX_RPC_CALL_SIZE 1024 * 1024

static const wchar_t* _protocol_sequence = L"ncalrpc";
static bool _rpc_server_initialized = false;

unsigned long
initialize_rpc_server()
{
    RPC_STATUS status;
    bool registered = false;
    RPC_BINDING_VECTOR* binding_vector = nullptr;
    void* security_descriptor = nullptr;

    // Only permit access from SDDL_BUILTIN_ADMINISTRATORS.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;;FA;;;BA)", SDDL_REVISION_1, &security_descriptor, nullptr)) {
        status = GetLastError();
        goto Exit;
    }

    status = RpcServerUseProtseq((RPC_WSTR)_protocol_sequence, RPC_C_PROTSEQ_MAX_REQS_DEFAULT, nullptr);
    if (status != RPC_S_OK) {
        goto Exit;
    }

    status = RpcServerRegisterIf3(
        EBPF_SERVICE_INTERFACE_HANDLE,
        nullptr,
        nullptr,
        RPC_IF_AUTOLISTEN,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        MAX_RPC_CALL_SIZE,
        nullptr,
        security_descriptor);
    LocalFree(security_descriptor);
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
