// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Windows.h needs to be included before other headers.
// It has a #define for WINAPI_FAMILY_PARTITION among others that control
// the behavior of other Windows headers.
#include <windows.h>

#include <ctype.h>
#include <iostream>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "rpc_interface_c.c"

#pragma comment(lib, "Rpcrt4.lib")

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
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_API,
            "RPC call ebpf_client_verify_and_load_program threw exception",
            RpcExceptionCode());
        result = EBPF_RPC_EXCEPTION;
    }
    RpcEndExcept

        return result;
}

RPC_STATUS
initialize_rpc_binding()
{
    RPC_WSTR string_binding = nullptr;
    RPC_SECURITY_QOS_V5 rpc_security_qos{
        RPC_C_SECURITY_QOS_VERSION_5,
        RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH,
        RPC_C_QOS_IDENTITY_DYNAMIC,
        RPC_C_IMP_LEVEL_IDENTIFY};

    RPC_STATUS status =
        RpcStringBindingCompose(nullptr, (RPC_WSTR)_protocol_sequence, nullptr, nullptr, nullptr, &string_binding);
    if (status != RPC_S_OK) {
        SetLastError(status);
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, RpcStringBindingCompose);
        goto Exit;
    }

    status = RpcBindingFromStringBinding(string_binding, &ebpf_service_interface_handle);
    if (status != RPC_S_OK) {
        SetLastError(status);
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, RpcBindingFromStringBinding);
        goto Exit;
    }

    // Service SID for eBPFSvc
    // S-1-5-80-3453964624-2861012444-1105579853-3193141192-1897355174
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;;FA;;;S-1-5-80-3453964624-2861012444-1105579853-3193141192-1897355174)",
            SDDL_REVISION_1,
            &rpc_security_qos.ServerSecurityDescriptor,
            nullptr)) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, ConvertStringSecurityDescriptorToSecurityDescriptorA);
        status = GetLastError();
        goto Exit;
    }

    if (!ConvertStringSidToSidA("LS", &rpc_security_qos.Sid)) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, ConvertStringSidToSidA);
        status = GetLastError();
        goto Exit;
    }

    status = RpcBindingSetAuthInfoEx(
        ebpf_service_interface_handle,
        nullptr,
        RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
        RPC_C_AUTHN_DEFAULT,
        nullptr,
        0,
        reinterpret_cast<RPC_SECURITY_QOS*>(&rpc_security_qos));
    if (status != RPC_S_OK) {
        SetLastError(status);
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, RpcBindingSetAuthInfoEx);
        goto Exit;
    }

    _binding_initialized = true;

Exit:
    RpcStringFree(&string_binding);
    if (status != RPC_S_OK && ebpf_service_interface_handle) {
        RpcBindingFree(&ebpf_service_interface_handle);
    };
    LocalFree(rpc_security_qos.ServerSecurityDescriptor);
    return status;
}

RPC_STATUS
clean_up_rpc_binding()
{
    if (!_binding_initialized) {
        return RPC_S_OK;
    }
    return RpcBindingFree(&ebpf_service_interface_handle);
}
