// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_registry_helper_um.h"

#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef _DEBUG
#define ebpf_assert(x) ASSERT(x)
#else
#define ebpf_assert(x) (void)(x)
#endif // !_DEBUG

static wchar_t*
_get_wstring_from_string(const char* text)
{
    ebpf_assert(text);
    size_t length = strlen(text) + 1;
    wchar_t* wide = (wchar_t*)malloc(length * sizeof(wchar_t));
    mbstowcs(wide, text, length);
    return wide;
}

void
close_registry_key(ebpf_registry_key_t key)
{
    ebpf_assert(key);
    RegCloseKey(key);
}

ebpf_registry_result_t
write_registry_value_binary(ebpf_registry_key_t key, const wchar_t* value_name, const uint8_t* value, size_t value_size)
{
    ebpf_assert(value_name);
    ebpf_assert(value);

    return RegSetValueEx(key, value_name, 0, REG_BINARY, value, (DWORD)value_size);
}

ebpf_registry_result_t
write_registry_value_wide_string(ebpf_registry_key_t key, const wchar_t* value_name, const wchar_t* value)
{
    ebpf_assert(value_name);
    ebpf_assert(value);

    size_t length = (wcslen(value) + 1) * sizeof(wchar_t);
    return RegSetValueEx(key, value_name, 0, REG_SZ, (const BYTE*)value, (DWORD)length);
}

ebpf_registry_result_t
write_registry_value_ansi_string(ebpf_registry_key_t key, const wchar_t* value_name, const char* value)
{
    uint32_t result = ERROR_SUCCESS;

    wchar_t* wide_string = _get_wstring_from_string(value);
    if (wide_string == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    result = write_registry_value_wide_string(key, value_name, wide_string);
    free(wide_string);

    return result;
}

ebpf_registry_result_t
write_registry_value_dword(ebpf_registry_key_t key, const wchar_t* value_name, uint32_t value)
{
    ebpf_assert(key);
    return RegSetValueEx(key, value_name, 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
}

ebpf_registry_result_t
create_registry_key(ebpf_registry_key_t root_key, const wchar_t* sub_key, uint32_t flags, ebpf_registry_key_t* key)
{
    *key = NULL;
    if (root_key == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    return RegCreateKeyEx(root_key, sub_key, 0, NULL, 0, flags, NULL, key, NULL);
}

uint32_t
open_registry_key(ebpf_registry_key_t root_key, const wchar_t* sub_key, uint32_t flags, ebpf_registry_key_t* key)
{
    ebpf_assert(root_key != NULL);
    return RegOpenKeyEx(root_key, sub_key, 0, flags, key);
}

ebpf_registry_result_t
delete_registry_key(ebpf_registry_key_t root_key, const wchar_t* sub_key)
{
    return RegDeleteKeyEx(root_key, sub_key, 0, 0);
}

ebpf_registry_result_t
delete_registry_tree(ebpf_registry_key_t root_key, const wchar_t* sub_key)
{
    return RegDeleteTree(root_key, sub_key);
}

ebpf_registry_result_t
create_registry_key_ansi(ebpf_registry_key_t root_key, const char* sub_key, uint32_t flags, ebpf_registry_key_t* key)
{
    uint32_t result = ERROR_SUCCESS;

    wchar_t* wide_string = _get_wstring_from_string(sub_key);
    if (wide_string == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    result = create_registry_key(root_key, wide_string, flags, key);
    free(wide_string);

    return result;
}

ebpf_registry_result_t
read_registry_value_string(ebpf_registry_key_t key, const wchar_t* value_name, wchar_t** value)
{
    uint32_t status = ERROR_SUCCESS;
    DWORD type = REG_SZ;
    DWORD value_size = 0;
    wchar_t* string_value = NULL;

    *value = NULL;
    status = RegQueryValueEx(key, value_name, 0, &type, NULL, &value_size);
    if (status != ERROR_SUCCESS || type != REG_SZ) {
        if (type != REG_SZ) {
            status = ERROR_INVALID_PARAMETER;
        }
        return status;
    }

    string_value = (wchar_t*)malloc(value_size + sizeof(wchar_t));
    if (string_value == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    memset(string_value, 0, value_size + sizeof(wchar_t));
    status = RegQueryValueEx(key, value_name, 0, &type, (BYTE*)string_value, &value_size);
    if (status != ERROR_SUCCESS) {
        free(string_value);
        return status;
    }
    *value = string_value;

    return status;
}

ebpf_registry_result_t
read_registry_value_dword(ebpf_registry_key_t key, const wchar_t* value_name, uint32_t* value)
{
    DWORD type = REG_DWORD;
    DWORD value_size = sizeof(uint32_t);
    return RegQueryValueEx(key, value_name, 0, &type, (BYTE*)value, &value_size);
}

ebpf_registry_result_t
read_registry_value_binary(ebpf_registry_key_t key, const wchar_t* value_name, uint8_t* value, size_t value_size)
{
    DWORD status = NO_ERROR;
    DWORD type = REG_BINARY;
    DWORD local_value_size = (DWORD)value_size;

    status = RegQueryValueEx(key, value_name, 0, &type, value, &local_value_size);
    if (status != ERROR_SUCCESS || type != REG_BINARY || local_value_size != value_size) {
        if (status != ERROR_SUCCESS) {
            status = ERROR_INVALID_PARAMETER;
        }
        return status;
    }

    return status;
}

ebpf_registry_result_t
convert_guid_to_string(const GUID* guid, wchar_t* string, size_t string_size)
{
    if (string_size < GUID_STRING_LENGTH + 1) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    // Convert program type GUID to string.
    RPC_WSTR value_name = NULL;
    RPC_STATUS rpc_status = UuidToString((GUID*)guid, &value_name);
    if (rpc_status != RPC_S_OK) {
        return ERROR_INVALID_PARAMETER;
    }

    // UuidToString returns string without braces. Add braces to the resulting string.

    // Copy the buffer to the output string.
    wcsncpy_s(string, string_size, (wchar_t*)value_name, GUID_STRING_LENGTH);
    string[GUID_STRING_LENGTH] = L'\0';
    RpcStringFree(&value_name);

    return ERROR_SUCCESS;
}

ebpf_registry_result_t
convert_string_to_guid(const wchar_t* string, GUID* guid)
{
    // The UUID string read from the registry also contains the opening and closing braces.
    // Remove those before converting to UUID.
    wchar_t truncated_string[GUID_STRING_LENGTH + 1] = {0};
    wcsncpy_s(truncated_string, sizeof(truncated_string) / sizeof(wchar_t), string + 1, wcslen(string) - 2);

    // Convert program type string to GUID
    RPC_STATUS rpc_status = UuidFromString((RPC_WSTR)truncated_string, guid);
    if (rpc_status != RPC_S_OK) {
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}
