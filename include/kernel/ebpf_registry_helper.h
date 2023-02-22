// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "framework.h"

#define __return_type NTSTATUS
#define _SUCCESS STATUS_SUCCESS
#define IS_SUCCESS(x) (NT_SUCCESS(x))

#define REG_CREATE_FLAGS 0
#define GUID_STRING_LENGTH 38 // not including the null terminator.

typedef _Return_type_success_(NT_SUCCESS(return )) uint32_t ebpf_registry_result_t;

typedef HANDLE ebpf_registry_key_t;

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Mocks for building platform_kernel & netebpfext when including the common ebpf_store_helper.h in kernel mode.
// Currently these prototypes only need (existing) implementations in user mode, as they are not referenced in kernel
// binaries.
_Success_(return == STATUS_SUCCESS) uint32_t open_registry_key(
    ebpf_registry_key_t root_key, _In_opt_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key);
_Must_inspect_result_ ebpf_registry_result_t
delete_registry_key(ebpf_registry_key_t root_key, _In_z_ const wchar_t* sub_key);
_Must_inspect_result_ ebpf_registry_result_t
delete_registry_tree(ebpf_registry_key_t root_key, _In_opt_z_ const wchar_t* sub_key);
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void
close_registry_key(ebpf_registry_key_t key)
{
    ZwClose(key);
}

static NTSTATUS
convert_guid_to_string(_In_ const GUID* guid, _Out_writes_all_(string_length) wchar_t* string, size_t string_length)
{
    UNICODE_STRING unicode_string = {0};

    NTSTATUS status = RtlStringFromGUID(guid, &unicode_string);
    if (status != STATUS_SUCCESS) {
        goto Exit;
    }

    if (string_length < GUID_STRING_LENGTH + 1) {
        status = STATUS_BUFFER_TOO_SMALL;
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
    return status;
}

static _Must_inspect_result_ ebpf_registry_result_t
write_registry_value_binary(
    ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _In_reads_(value_size) uint8_t* value, size_t value_size)
{
    UNICODE_STRING unicode_value_name;

    RtlInitUnicodeString(&unicode_value_name, value_name);
    return ZwSetValueKey(key, &unicode_value_name, 0, REG_BINARY, value, (ULONG)value_size);
}

static _Must_inspect_result_ ebpf_registry_result_t
write_registry_value_ansi_string(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _In_z_ const char* value)
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
    return status;
}

static _Must_inspect_result_ ebpf_registry_result_t
write_registry_value_dword(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, uint32_t value)
{
    UNICODE_STRING unicode_name;
    RtlInitUnicodeString(&unicode_name, value_name);
    return ZwSetValueKey(key, &unicode_name, 0, REG_DWORD, &value, sizeof(uint32_t));
}

static _Must_inspect_result_ ebpf_registry_result_t
create_registry_key(
    ebpf_registry_key_t root_key, _In_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING registry_path;
    OBJECT_ATTRIBUTES object_attributes = {0};

    UNREFERENCED_PARAMETER(flags);

    RtlInitUnicodeString(&registry_path, sub_key);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_key, NULL);

    status = ZwCreateKey(key, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

    return status;
}

static _Must_inspect_result_ ebpf_registry_result_t
create_registry_key_ansi(
    ebpf_registry_key_t root_key, _In_z_ const char* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key)
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
    return status;
}
