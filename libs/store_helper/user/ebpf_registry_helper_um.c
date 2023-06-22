// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include "ebpf_registry_helper_um.h"
//#include <Windows.h>
#include <winreg.h>

void
close_registry_key(ebpf_registry_key_t key)
{
    RegCloseKey(key);
}

_Must_inspect_result_ ebpf_registry_result_t
convert_guid_to_string(_In_ const GUID* guid, _Out_writes_all_(string_length) wchar_t* string, size_t string_length)
{
    if (guid == NULL || string == NULL || string_length == 0)
        return ERROR_INVALID_PARAMETER;

    if (StringFromGUID2(guid, string, string_length) == 0) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

_Must_inspect_result_ ebpf_registry_result_t
write_registry_value_binary(
    ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _In_reads_(value_size) uint8_t* value, size_t value_size)
{
    return RegSetValueExW(key, value_name, 0, REG_BINARY, value, value_size);
}

_Must_inspect_result_ ebpf_registry_result_t
write_registry_value_ansi_string(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _In_z_ const char* value)
{
    wchar_t unicode_value[MAX_PATH];
    size_t value_length = strlen(value) + 1;
    MultiByteToWideChar(CP_ACP, 0, value, -1, unicode_value, MAX_PATH);

    LSTATUS status =
        RegSetValueExW(key, value_name, 0, REG_SZ, (const BYTE*)unicode_value, value_length * sizeof(wchar_t));
    if (status != ERROR_SUCCESS) {
        return status;
    }

    return ERROR_SUCCESS;
}

_Must_inspect_result_ ebpf_registry_result_t
write_registry_value_dword(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, uint32_t value)
{
    return RegSetValueExW(key, value_name, 0, REG_DWORD, (const BYTE*)&value, sizeof(uint32_t));
}

_Must_inspect_result_ ebpf_registry_result_t
create_registry_key(
    ebpf_registry_key_t root_key, _In_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key)
{
    return RegCreateKeyExW(root_key, sub_key, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, key, NULL);
}

_Must_inspect_result_ ebpf_registry_result_t
create_registry_key_ansi(
    ebpf_registry_key_t root_key, _In_z_ const char* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key)
{
    wchar_t unicode_sub_key[MAX_PATH];
    size_t sub_key_length = strlen(sub_key) + 1;
    MultiByteToWideChar(CP_ACP, 0, sub_key, -1, unicode_sub_key, MAX_PATH);

    LSTATUS status =
        RegCreateKeyExW(root_key, unicode_sub_key, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, key, NULL);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    return ERROR_SUCCESS;
}
