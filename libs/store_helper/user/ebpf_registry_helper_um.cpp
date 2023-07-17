// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Contains user mode registry related helper APIs.
 */

#include "ebpf_platform.h"
#include "ebpf_registry_helper_um.h"

#include <string>

#define GUID_STRING_LENGTH 38 // not including the null terminator.

static std::wstring
_get_wstring_from_string(std::string text)
{
    // This is deprecated
    // std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    // std::wstring wide = converter.from_bytes(text);
    // return wide;

    int length = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    std::wstring wide(length, 0);
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &wide[0], length);

    return wide;
}

void
close_registry_key(ebpf_registry_key_t key)
{
    ebpf_assert(key);
    RegCloseKey(key);
}

_Must_inspect_result_ ebpf_registry_result_t
write_registry_value_binary(
    ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _In_reads_(value_size) uint8_t* value, size_t value_size)
{
    ebpf_assert(value_name);
    ebpf_assert(value);

    return RegSetValueEx(key, value_name, 0, REG_BINARY, value, (unsigned long)value_size);
}

_Must_inspect_result_ ebpf_registry_result_t
write_registry_value_wide_string(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _In_z_ const wchar_t* value)
{
    ebpf_assert(value_name);
    ebpf_assert(value);

    auto length = (wcslen(value) + 1) * sizeof(wchar_t);
    return RegSetValueEx(key, value_name, 0, REG_SZ, (uint8_t*)value, (unsigned long)length);
}

_Must_inspect_result_ ebpf_registry_result_t
write_registry_value_ansi_string(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _In_z_ const char* value)
{
    uint32_t result;
    try {
        auto wide_string = _get_wstring_from_string(value);
        result = write_registry_value_wide_string(key, value_name, wide_string.c_str());
    } catch (...) {
        result = ERROR_NOT_ENOUGH_MEMORY;
    }

    return result;
}

_Must_inspect_result_ ebpf_registry_result_t
write_registry_value_dword(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, uint32_t value)
{
    ebpf_assert(key);
    return RegSetValueEx(key, value_name, 0, REG_DWORD, (PBYTE)&value, sizeof(value));
}

_Must_inspect_result_ ebpf_registry_result_t
create_registry_key(
    ebpf_registry_key_t root_key, _In_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key)
{
    *key = nullptr;
    if (root_key == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    return RegCreateKeyEx(root_key, sub_key, 0, nullptr, 0, flags, nullptr, key, nullptr);
}

_Success_(return == ERROR_SUCCESS) uint32_t open_registry_key(
    ebpf_registry_key_t root_key, _In_opt_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key)
{
    ebpf_assert(root_key != nullptr);
    _Analysis_assume_(root_key != nullptr);

    return RegOpenKeyEx(root_key, sub_key, 0, flags, key);
}

_Must_inspect_result_ ebpf_registry_result_t
delete_registry_key(ebpf_registry_key_t root_key, _In_z_ const wchar_t* sub_key)
{
    return RegDeleteKeyEx(root_key, sub_key, 0, 0);
}

_Must_inspect_result_ ebpf_registry_result_t
delete_registry_tree(ebpf_registry_key_t root_key, _In_opt_z_ const wchar_t* sub_key)
{
    return RegDeleteTree(root_key, sub_key);
}

_Must_inspect_result_ ebpf_registry_result_t
create_registry_key_ansi(
    ebpf_registry_key_t root_key, _In_z_ const char* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key)
{
    uint32_t result;
    try {
        auto wide_string = _get_wstring_from_string(sub_key);
        result = create_registry_key(root_key, wide_string.c_str(), flags, key);
    } catch (...) {
        result = ERROR_NOT_ENOUGH_MEMORY;
    }

    return result;
}

_Must_inspect_result_ ebpf_registry_result_t
read_registry_value_string(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _Outptr_result_z_ wchar_t** value)
{
    uint32_t status = ERROR_SUCCESS;
    unsigned long type = REG_SZ;
    unsigned long value_size = 0;
    wchar_t* string_value = nullptr;

    *value = nullptr;
    status = RegQueryValueEx(key, value_name, 0, &type, nullptr, &value_size);
    if (status != ERROR_SUCCESS || type != REG_SZ) {
        if (type != REG_SZ) {
            status = ERROR_INVALID_PARAMETER;
        }
        return status;
    }

    string_value = (wchar_t*)ebpf_allocate((value_size + sizeof(wchar_t)));
    if (string_value == nullptr) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    memset(string_value, 0, value_size + sizeof(wchar_t));
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
    return status;
}

_Must_inspect_result_ ebpf_registry_result_t
read_registry_value_dword(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _Out_ uint32_t* value)
{
    unsigned long type = REG_QWORD;
    unsigned long value_size = sizeof(uint32_t);
    return RegQueryValueEx(key, value_name, 0, &type, (PBYTE)value, &value_size);
}

_Must_inspect_result_ ebpf_registry_result_t
read_registry_value_binary(
    ebpf_registry_key_t key,
    _In_z_ const wchar_t* value_name,
    _Out_writes_(value_size) uint8_t* value,
    size_t value_size)
{
    uint32_t status = NO_ERROR;
    unsigned long type = REG_BINARY;
    unsigned long local_value_size = (unsigned long)value_size;

    status = RegQueryValueEx(key, value_name, 0, &type, value, &local_value_size);
    if (status != ERROR_SUCCESS || type != REG_BINARY || local_value_size != value_size) {
        if (status != ERROR_SUCCESS) {
            status = ERROR_INVALID_PARAMETER;
        }
        goto Exit;
    }

Exit:
    return status;
}

_Must_inspect_result_ ebpf_registry_result_t
convert_guid_to_string(_In_ const GUID* guid, _Out_writes_all_(string_size) wchar_t* string, size_t string_size)
{
    uint32_t status = ERROR_SUCCESS;
    wchar_t* value_name = nullptr;

    try {
        if (string_size < GUID_STRING_LENGTH + 1) {
            return ERROR_INSUFFICIENT_BUFFER;
        }

        // Convert program type GUID to string.
        RPC_STATUS rpc_status = UuidToString(guid, (RPC_WSTR*)&value_name);
        if (rpc_status != RPC_S_OK) {
            return ERROR_INVALID_PARAMETER;
        }

        std::wstring value_name_string(value_name);

        // UuidToString returns string without braces. Add braces to the resulting string.
        value_name_string = L"{" + value_name_string + L"}";

        // Copy the buffer to the output string.
        memcpy(string, value_name_string.c_str(), GUID_STRING_LENGTH * 2);
        string[GUID_STRING_LENGTH] = L'\0';
    } catch (...) {
        status = ERROR_NOT_ENOUGH_MEMORY;
    }

    return status;
}

_Must_inspect_result_ ebpf_registry_result_t
convert_string_to_guid(_In_z_ const wchar_t* string, _Out_ GUID* guid)
{
    uint32_t status = ERROR_SUCCESS;

    // The UUID string read from registry also contains the opening and closing braces.
    // Remove those before converting to UUID.
    wchar_t truncated_string[GUID_STRING_LENGTH + 1] = {0};
    memcpy(truncated_string, string + 1, (wcslen(string) - 2) * sizeof(wchar_t));

    // Convert program type string to GUID
    auto rpc_status = UuidFromString((RPC_WSTR)truncated_string, guid);
    if (rpc_status != RPC_S_OK) {
        status = ERROR_INVALID_PARAMETER;
    }

    return status;
}
