// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Contains user mode registry related helper APIs.
 */

#include "ebpf_registry_helper.h"
#include "ebpf_shared_framework.h"
#include "ebpf_windows.h"

#include <rpc.h>
#include <string>

#define GUID_STRING_LENGTH 38 // not including the null terminator.
#define _EBPF_RESULT(x) win32_error_code_to_ebpf_result(x)

ebpf_store_key_t ebpf_store_root_key = HKEY_CURRENT_USER; // TODO: Issue #1231 Change to using HKEY_LOCAL_MACHINE
const wchar_t* ebpf_store_root_sub_key = EBPF_ROOT_RELATIVE_PATH;

wchar_t*
ebpf_get_wstring_from_string(_In_ const char* text)
{
    int length = MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
    wchar_t* wide = (wchar_t*)ebpf_allocate(length * sizeof(wchar_t));
    if (wide == nullptr) {
        return nullptr;
    }
    MultiByteToWideChar(CP_UTF8, 0, text, -1, wide, length);

    return wide;
}

void
ebpf_free_wstring(_Frees_ptr_opt_ wchar_t* wide)
{
    ebpf_free(wide);
}

void
ebpf_close_registry_key(ebpf_store_key_t key)
{
    if (key != NULL) {
        RegCloseKey(key);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_write_registry_value_binary(
    ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _In_reads_(value_size) uint8_t* value, size_t value_size)
{
    ebpf_assert(value_name);
    ebpf_assert(value);

    return _EBPF_RESULT(RegSetValueEx(key, value_name, 0, REG_BINARY, value, (unsigned long)value_size));
}

_Must_inspect_result_ ebpf_result_t
ebpf_write_registry_value_string(ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _In_z_ const wchar_t* value)
{
    ebpf_assert(value_name);
    ebpf_assert(value);

    auto length = (wcslen(value) + 1) * sizeof(wchar_t);
    return _EBPF_RESULT(RegSetValueEx(key, value_name, 0, REG_SZ, (uint8_t*)value, (unsigned long)length));
}

_Must_inspect_result_ ebpf_result_t
ebpf_write_registry_value_dword(ebpf_store_key_t key, _In_z_ const wchar_t* value_name, uint32_t value)
{
    ebpf_assert(key);
    return _EBPF_RESULT(RegSetValueEx(key, value_name, 0, REG_DWORD, (PBYTE)&value, sizeof(value)));
}

_Must_inspect_result_ ebpf_result_t
ebpf_create_registry_key(
    ebpf_store_key_t root_key, _In_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_store_key_t* key)
{
    *key = nullptr;
    if (root_key == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    return _EBPF_RESULT(RegCreateKeyEx(root_key, sub_key, 0, nullptr, 0, flags, nullptr, key, nullptr));
}

_Must_inspect_result_ ebpf_result_t
ebpf_open_registry_key(
    ebpf_store_key_t root_key, _In_opt_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_store_key_t* key)
{
    ebpf_assert(root_key != nullptr);
    _Analysis_assume_(root_key != nullptr);

    return _EBPF_RESULT(RegOpenKeyEx(root_key, sub_key, 0, flags, key));
}

_Must_inspect_result_ ebpf_result_t
ebpf_delete_registry_key(ebpf_store_key_t root_key, _In_z_ const wchar_t* sub_key)
{
    return _EBPF_RESULT(RegDeleteKeyEx(root_key, sub_key, 0, 0));
}

_Must_inspect_result_ ebpf_result_t
ebpf_delete_registry_tree(ebpf_store_key_t root_key, _In_opt_z_ const wchar_t* sub_key)
{
    return _EBPF_RESULT(RegDeleteTreeW(root_key, sub_key));
}

_Must_inspect_result_ ebpf_result_t
ebpf_read_registry_value_string(
    ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _Outptr_result_maybenull_ wchar_t** value)
{
    ebpf_result_t result = EBPF_SUCCESS;
    unsigned long type = REG_SZ;
    unsigned long value_size = 0;
    wchar_t* string_value = nullptr;

    if (value == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    *value = nullptr;
    result = _EBPF_RESULT(RegQueryValueEx(key, value_name, 0, &type, nullptr, &value_size));
    if (result != EBPF_SUCCESS || type != REG_SZ) {
        if (type != REG_SZ) {
            result = EBPF_INVALID_ARGUMENT;
        }
        return result;
    }

    string_value = (wchar_t*)ebpf_allocate((value_size + sizeof(wchar_t)));
    if (string_value == nullptr) {
        return EBPF_NO_MEMORY;
    }

    memset(string_value, 0, value_size + sizeof(wchar_t));
    result = _EBPF_RESULT(RegQueryValueEx(key, value_name, 0, &type, (PBYTE)string_value, &value_size));
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    *value = string_value;
    string_value = nullptr;

Exit:
    if (string_value) {
        ebpf_free(string_value);
    }
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_read_registry_value_dword(ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _Out_ uint32_t* value)
{
    unsigned long type = REG_QWORD;
    unsigned long value_size = sizeof(uint32_t);
    return _EBPF_RESULT(RegQueryValueEx(key, value_name, 0, &type, (PBYTE)value, &value_size));
}

_Must_inspect_result_ ebpf_result_t
ebpf_read_registry_value_binary(
    ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _Out_writes_(value_size) uint8_t* value, size_t value_size)
{
    ebpf_result_t result = EBPF_SUCCESS;
    unsigned long type = REG_BINARY;
    unsigned long local_value_size = (unsigned long)value_size;

    result = _EBPF_RESULT(RegQueryValueEx(key, value_name, 0, &type, value, &local_value_size));
    if (result != EBPF_SUCCESS || type != REG_BINARY || local_value_size != value_size) {
        if (result != EBPF_SUCCESS) {
            result = EBPF_INVALID_ARGUMENT;
        }
        goto Exit;
    }

Exit:
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_convert_guid_to_string(_In_ const GUID* guid, _Out_writes_all_(string_size) wchar_t* string, size_t string_size)
{
    ebpf_result_t result = EBPF_SUCCESS;
    wchar_t* value_name = nullptr;

    try {
        *string = 0;

        if (string_size < GUID_STRING_LENGTH + 1) {
            return EBPF_INSUFFICIENT_BUFFER;
        }

        // Convert program type GUID to string.
        RPC_STATUS rpc_status = UuidToString(guid, (RPC_WSTR*)&value_name);
        if (rpc_status != RPC_S_OK) {
            return EBPF_INVALID_ARGUMENT;
        }

        std::wstring value_name_string(value_name);

        // UuidToString returns string without braces. Add braces to the resulting string.
        value_name_string = L"{" + value_name_string + L"}";

        // Copy the buffer to the output string.
        memcpy(string, value_name_string.c_str(), GUID_STRING_LENGTH * 2);
        string[GUID_STRING_LENGTH] = L'\0';
    } catch (...) {
        result = EBPF_NO_MEMORY;
    }

    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_convert_string_to_guid(_In_z_ const wchar_t* string, _Out_ GUID* guid)
{
    ebpf_result_t result = EBPF_SUCCESS;

    // The UUID string read from registry also contains the opening and closing braces.
    // Remove those before converting to UUID.
    wchar_t truncated_string[GUID_STRING_LENGTH + 1] = {0};
    memcpy(truncated_string, string + 1, (wcslen(string) - 2) * sizeof(wchar_t));

    // Convert program type string to GUID
    auto rpc_status = UuidFromString((RPC_WSTR)truncated_string, guid);
    if (rpc_status != RPC_S_OK) {
        result = EBPF_INVALID_ARGUMENT;
    }

    return result;
}
