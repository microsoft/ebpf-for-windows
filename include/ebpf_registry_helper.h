// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <ntddk.h>

#define EBPF_ROOT_REGISTRY_PATH L"\\Registry\\Machine\\Software\\eBPF"

#define EBPF_PROVIDERS_REGISTRY_PATH L"Providers"
#define EBPF_SECTIONS_REGISTRY_PATH L"SectionData"
#define EBPF_PROGRAM_DATA_REGISTRY_PATH L"ProgramData"
#define EBPF_PROGRAM_DATA_HELPERS_REGISTRY_PATH L"Helpers"
#define EBPF_GLOBAL_HELPERS_REGISTRY_PATH L"GlobalHelpers"

#define EBPF_SECTION_DATA_PROGRAM_TYPE L"ProgramType"
#define EBPF_SECTION_DATA_ATTACH_TYPE L"AttachType"

#define EBPF_PROGRAM_DATA_NAME L"Name"
#define EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR L"ContextDescriptor"
#define EBPF_PROGRAM_DATA_PLATFORM_SPECIFIC_DATA L"PlatformSpecificData"
#define EBPF_PROGRAM_DATA_PRIVELEGED L"IsPrivileged"
#define EBPF_PROGRAM_DATA_BPF_PROG_TYPE L"BpfProgType"
#define EBPF_PROGRAM_DATA_HELPER_COUNT L"HelperCount"

#define EBPF_HELPER_DATA_PROTOTYPE L"Prototype"

#define REG_CREATE_FLAGS 0

#define GUID_STRING_LENGTH 38 // not inlcuding the null terminator.

typedef struct _ebpf_registry_key
{
    HANDLE key;
} ebpf_registry_key_t;

static void
close_registry_handle(_In_ ebpf_registry_key_t* key)
{
    if (key->key != NULL) {
        ZwClose(key->key);
        key->key = NULL;
    }
}

static uint32_t
convert_guid_to_string(_In_ const GUID* guid, _Out_ wchar_t* string)
{
    UNICODE_STRING unicode_string;
    uint32_t status = RtlStringFromGUID(guid, &unicode_string);
    if (status != STATUS_SUCCESS) {
        goto Exit;
    }

    // Copy the buffer to the output string.
    memcpy(string, unicode_string.Buffer, GUID_STRING_LENGTH * 2);
    string[GUID_STRING_LENGTH] = L'\0';

Exit:
    return status;
}

static uint32_t
write_registry_value_binary(
    _In_ const ebpf_registry_key_t* key,
    _In_ const wchar_t* value_name,
    _In_reads_(value_size) uint8_t* value,
    _In_ size_t value_size)
{
    UNICODE_STRING unicode_value_name;

    RtlInitUnicodeString(&unicode_value_name, value_name);
    return ZwSetValueKey(key->key, &unicode_value_name, 0, REG_BINARY, value, (ULONG)value_size);
}

static uint32_t
write_registry_value_ansi_string(
    _In_ const ebpf_registry_key_t* key, _In_ const wchar_t* value_name, _In_z_ const char* value)
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

    status = ZwSetValueKey(key->key, &unicode_value_name, 0, REG_SZ, unicode_value.Buffer, unicode_value.Length);
    RtlFreeUnicodeString(&unicode_value);

Exit:
    return status;
}

static uint32_t
write_registry_value_dword(_In_ const ebpf_registry_key_t* key, _In_z_ const wchar_t* value_name, uint32_t value)
{
    UNICODE_STRING unicode_name;
    RtlInitUnicodeString(&unicode_name, value_name);
    return ZwSetValueKey(key->key, &unicode_name, 0, REG_DWORD, &value, sizeof(uint32_t));
}

/*
static uint32_t
open_or_create_provider_registry_key(_Out_ ebpf_registry_key_t* provider_key)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE root_handle = NULL;
    HANDLE provider_handle = NULL;
    UNICODE_STRING registry_path;
    OBJECT_ATTRIBUTES object_attributes = {0};

    // Open (or create) root eBPF registry path.
    RtlInitUnicodeString(&registry_path, EBPF_ROOT_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateKey(&root_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Open (or create) provider registry path.
    RtlInitUnicodeString(&registry_path, EBPF_PROVIDERS_REGISTRY_PATH);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_handle, NULL);

    status = ZwCreateKey(&provider_handle, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    provider_key->key = provider_handle;
    provider_handle = NULL;

Exit:
    if (provider_handle) {
        ZwClose(provider_handle);
    }
    if (root_handle) {
        ZwClose(root_handle);
    }
    return status;
}
*/

static uint32_t
create_registry_key(
    _In_opt_ const ebpf_registry_key_t* root_key,
    _In_ const wchar_t* sub_key,
    uint32_t flags,
    _Out_ ebpf_registry_key_t* key)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING registry_path;
    OBJECT_ATTRIBUTES object_attributes = {0};
    HANDLE root_handle = root_key ? root_key->key : NULL;

    UNREFERENCED_PARAMETER(flags);

    RtlInitUnicodeString(&registry_path, sub_key);
    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_handle, NULL);

    status = ZwCreateKey(&key->key, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    return status;
}

static uint32_t
create_registry_key_ansi(
    _In_ const ebpf_registry_key_t* root_key,
    _In_z_ const char* sub_key,
    uint32_t flags,
    _Out_ ebpf_registry_key_t* key)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING registry_path;
    OBJECT_ATTRIBUTES object_attributes = {0};
    ANSI_STRING ansi_string;
    RtlInitAnsiString(&ansi_string, sub_key);

    UNREFERENCED_PARAMETER(flags);

    status = RtlAnsiStringToUnicodeString(&registry_path, &ansi_string, TRUE);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    InitializeObjectAttributes(
        &object_attributes, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, root_key->key, NULL);

    status = ZwCreateKey(&key->key, KEY_WRITE, &object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    RtlFreeUnicodeString(&registry_path);

Exit:
    return status;
}

/*
static uint32_t
open_registry_key(_In_ HKEY root_key, _In_ const wchar_t* sub_key, uint32_t flags, _Out_ HKEY* key)
{
    return RegOpenKeyEx(root_key, sub_key, 0, flags, key);
}
*/
