// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "platform.h"

#define __return_type uint32_t
#define IS_SUCCESS(x) (x == ERROR_SUCCESS)
#define _SUCCESS NO_ERROR

#define GUID_STRING_LENGTH 38 // not including the null terminator.

#define REG_CREATE_FLAGS (KEY_WRITE | DELETE | KEY_READ)
#define REG_OPEN_FLAGS (DELETE | KEY_READ)

typedef _Return_type_success_(return == 0) uint32_t ebpf_registry_result_t;

typedef HKEY ebpf_registry_key_t;

// Issue: #1542 - All API's should be annotated with _Must_inspect_result_

void
close_registry_key(ebpf_registry_key_t key);

_Must_inspect_result_ ebpf_registry_result_t
write_registry_value_binary(
    ebpf_registry_key_t key,
    _In_z_ const wchar_t* value_name,
    _In_reads_(value_size) uint8_t* value,
    size_t value_size);

_Must_inspect_result_ ebpf_registry_result_t
write_registry_value_ansi_string(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _In_z_ const char* value);

_Must_inspect_result_ ebpf_registry_result_t
write_registry_value_dword(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, uint32_t value);

_Must_inspect_result_ ebpf_registry_result_t
create_registry_key(
    ebpf_registry_key_t root_key, _In_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key);

_Success_(return == ERROR_SUCCESS) uint32_t open_registry_key(
    ebpf_registry_key_t root_key, _In_opt_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key);

_Must_inspect_result_ ebpf_registry_result_t
delete_registry_key(ebpf_registry_key_t root_key, _In_z_ const wchar_t* sub_key);

_Must_inspect_result_ ebpf_registry_result_t
delete_registry_tree(ebpf_registry_key_t root_key, _In_opt_z_ const wchar_t* sub_key);

_Must_inspect_result_ ebpf_registry_result_t
read_registry_value_dword(ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _Out_ uint32_t* value);

_Must_inspect_result_ ebpf_registry_result_t
read_registry_value_binary(
    ebpf_registry_key_t key,
    _In_z_ const wchar_t* value_name,
    _Out_writes_(value_size) uint8_t* value,
    size_t value_size);

_Must_inspect_result_ ebpf_registry_result_t
convert_guid_to_string(_In_ const GUID* guid, _Out_writes_all_(string_size) wchar_t* string, size_t string_size);

_Must_inspect_result_ ebpf_registry_result_t
convert_string_to_guid(_In_z_ const wchar_t* string, _Out_ GUID* guid);

_Must_inspect_result_ ebpf_registry_result_t
create_registry_key_ansi(
    ebpf_registry_key_t root_key, _In_z_ const char* sub_key, uint32_t flags, _Out_ ebpf_registry_key_t* key);

_Must_inspect_result_ ebpf_registry_result_t
read_registry_value_string(
    ebpf_registry_key_t key, _In_z_ const wchar_t* value_name, _Outptr_result_z_ wchar_t** value);
