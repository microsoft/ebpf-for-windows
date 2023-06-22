// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "framework.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define __return_type NTSTATUS
#define _SUCCESS STATUS_SUCCESS
#define IS_SUCCESS(x) (NT_SUCCESS(x))

#define REG_CREATE_FLAGS 0
#define GUID_STRING_LENGTH 38 // not including the null terminator.

    typedef HANDLE ebpf_registry_key_t;
    typedef _Return_type_success_(NT_SUCCESS(return )) uint32_t ebpf_registry_result_t;

    NTSTATUS
    convert_guid_to_string(
        _In_ const GUID* guid, _Out_writes_all_(string_length) wchar_t* string, size_t string_length);

    void
    close_registry_key(ebpf_registry_key_t key);

    _Must_inspect_result_ ebpf_registry_result_t
    write_registry_value_binary(
        ebpf_registry_key_t key,
        _In_z_ const wchar_t* value_name,
        _In_reads_(value_size) uint8_t* value,
        size_t value_size);

    _Must_inspect_result_ ebpf_registry_result_t
    write_registry_value_ansi_string(
        ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _In_z_ const char* value);

    _Must_inspect_result_ ebpf_registry_result_t
    write_registry_value_dword(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, uint32_t value);

    _Must_inspect_result_ ebpf_registry_result_t
    create_registry_key(
        ebpf_registry_key_t root_key, _In_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key);

    _Must_inspect_result_ ebpf_registry_result_t
    create_registry_key_ansi(
        ebpf_registry_key_t root_key, _In_z_ const char* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key);

#ifdef __cplusplus
} /* extern "C" */
#endif