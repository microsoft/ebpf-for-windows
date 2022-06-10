// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Contains registry related helper APIs.

#include <map>
#include <mutex>
#include <stdexcept>
#include "api_common.hpp"
#include "device_helper.hpp"
#include "ebpf_api.h"
// #include "ebpf_bind_program_data.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
// #include "ebpf_xdp_program_data.h"
#include "platform.h"
#include "platform.hpp"

#include "registry_helper.hpp"

ebpf_result_t
read_registry_value_string(HKEY key, _In_ const wchar_t* value_name, _Out_ wchar_t** value)
{
    uint32_t status = NO_ERROR;
    DWORD type = REG_SZ;
    DWORD value_size = 0;
    wchar_t* string_value = nullptr;

    *value = nullptr;
    status = RegQueryValueEx(key, value_name, 0, &type, nullptr, &value_size);
    if (status != ERROR_SUCCESS || type != REG_SZ) {
        return win32_error_code_to_ebpf_result(status);
    }

    string_value = (wchar_t*)ebpf_allocate((value_size + sizeof(wchar_t)));
    if (string_value == nullptr) {
        status = ERROR_NOT_ENOUGH_MEMORY;
        return win32_error_code_to_ebpf_result(status);
    }

    status = RegQueryValueEx(key, value_name, 0, &type, (PBYTE)string_value, &value_size);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }
    *value = string_value;
    string_value = nullptr;

Exit:
    if (string_value) {
        ebpf_free(string_value);
    }
    return win32_error_code_to_ebpf_result(status);
}

ebpf_result_t
read_registry_value_dword(_In_ HKEY key, _In_ const wchar_t* value_name, _Out_ uint32_t* value)
{
    uint32_t status = NO_ERROR;
    DWORD type = REG_QWORD;
    DWORD key_size = sizeof(uint32_t);
    status = RegQueryValueEx(key, value_name, 0, &type, (PBYTE)value, &key_size);
    return win32_error_code_to_ebpf_result(status);
}

ebpf_result_t
read_registry_value_qword(_In_ HKEY key, _In_ const wchar_t* value_name, _Out_ uint64_t* value)
{
    uint32_t status = NO_ERROR;
    DWORD type = REG_QWORD;
    DWORD key_size = sizeof(uint64_t);
    status = RegQueryValueEx(key, value_name, 0, &type, (PBYTE)value, &key_size);
    return win32_error_code_to_ebpf_result(status);
}

ebpf_result_t
read_registry_value_binary(
    _In_ HKEY key, _In_ const wchar_t* value_name, _Out_writes_(value_size) uint8_t* value, _In_ size_t value_size)
{
    uint32_t status = NO_ERROR;
    DWORD type = REG_BINARY;
    DWORD local_value_size = (DWORD)value_size;

    // *value = NULL;
    status = RegQueryValueEx(key, value_name, 0, &type, value, &local_value_size);
    if (status != ERROR_SUCCESS || type != REG_BINARY || local_value_size != value_size) {
        if (status != ERROR_SUCCESS) {
            status = ERROR_INVALID_PARAMETER;
        }
        goto Exit;
    }

Exit:
    return win32_error_code_to_ebpf_result(status);
}
