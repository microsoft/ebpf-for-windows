// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Contains kernel mode registry related helper APIs.
 */

#include "ebpf_registry_helper.h"

#define _EBPF_RESULT(x) (NT_SUCCESS(x) ? EBPF_SUCCESS : EBPF_FAILED)

ebpf_result_t
ebpf_convert_guid_to_string(
    _In_ const GUID* guid, _Out_writes_all_(string_length) wchar_t* string, size_t string_length)
{
    UNICODE_STRING unicode_string = {0};

    ebpf_result_t result = _EBPF_RESULT(RtlStringFromGUID(guid, &unicode_string));
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (string_length < GUID_STRING_LENGTH + 1) {
        result = EBPF_INSUFFICIENT_BUFFER;
        goto Exit;
    }

    __analysis_assume(unicode_string.MaximumLength >= GUID_STRING_LENGTH * sizeof(wchar_t));
    __analysis_assume(unicode_string.Buffer != NULL);

    // Copy the buffer to the output string.
    memcpy(string, unicode_string.Buffer, GUID_STRING_LENGTH * sizeof(wchar_t));
    string[GUID_STRING_LENGTH] = L'\0';

Exit:
    if (unicode_string.Buffer != NULL) {
        RtlFreeUnicodeString(&unicode_string);
    }
    return result;
}

void
ebpf_close_registry_key(ebpf_store_key_t key)
{
    if (key) {
        ZwClose(key);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_write_registry_value_binary(
    ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _In_reads_(value_size) uint8_t* value, size_t value_size)
{
    UNICODE_STRING unicode_value_name;

    RtlInitUnicodeString(&unicode_value_name, value_name);
    return _EBPF_RESULT(ZwSetValueKey(key, &unicode_value_name, 0, REG_BINARY, value, (ULONG)value_size));
}

_Must_inspect_result_ ebpf_result_t
ebpf_write_registry_value_ansi_string(ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _In_z_ const char* value)
{
    NTSTATUS status;
    UNICODE_STRING unicode_value;
    UNICODE_STRING unicode_value_name;

    ANSI_STRING ansi_string;
    RtlInitAnsiString(&ansi_string, value);

    status = RtlAnsiStringToUnicodeString(&unicode_value, &ansi_string, TRUE);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    RtlInitUnicodeString(&unicode_value_name, value_name);

    status = ZwSetValueKey(key, &unicode_value_name, 0, REG_SZ, unicode_value.Buffer, unicode_value.Length);
    RtlFreeUnicodeString(&unicode_value);

Exit:
    return _EBPF_RESULT(status);
}

_Must_inspect_result_ ebpf_result_t
ebpf_write_registry_value_dword(ebpf_store_key_t key, _In_z_ const wchar_t* value_name, uint32_t value)
{
    UNICODE_STRING unicode_name;
    RtlInitUnicodeString(&unicode_name, value_name);
    return _EBPF_RESULT(ZwSetValueKey(key, &unicode_name, 0, REG_DWORD, &value, sizeof(uint32_t)));
}

_Must_inspect_result_ ebpf_result_t
ebpf_create_registry_key(
    ebpf_store_key_t root_key, _In_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_store_key_t* key)
{
    UNICODE_STRING registry_path;
    OBJECT_ATTRIBUTES object_attributes = {0};

    UNREFERENCED_PARAMETER(flags);

    RtlInitUnicodeString(&registry_path, sub_key);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_key, NULL);

    return _EBPF_RESULT(ZwCreateKey(key, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL));
}

_Must_inspect_result_ ebpf_result_t
ebpf_create_registry_key_ansi(
    ebpf_store_key_t root_key, _In_z_ const char* sub_key, uint32_t flags, _Out_ ebpf_store_key_t* key)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING registry_path;
    OBJECT_ATTRIBUTES object_attributes = {0};
    ANSI_STRING ansi_string;
    RtlInitAnsiString(&ansi_string, sub_key);

    UNREFERENCED_PARAMETER(flags);
    *key = NULL;

    status = RtlAnsiStringToUnicodeString(&registry_path, &ansi_string, TRUE);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_key, NULL);

    status = ZwCreateKey(key, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    RtlFreeUnicodeString(&registry_path);

Exit:
    return _EBPF_RESULT(status);
}
