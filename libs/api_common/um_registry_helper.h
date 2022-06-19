// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <windows.h>
#include "ebpf_api.h"
#include "platform.h"

#define GUID_STRING_LENGTH 38

#define REG_CREATE_FLAGS (KEY_WRITE | DELETE | KEY_READ)
#define REG_OPEN_FLAGS (DELETE | KEY_READ)

typedef struct _ebpf_registry_key
{
    HKEY key;
} ebpf_registry_key_t;

void
close_registry_key(_In_ ebpf_registry_key_t* key);

uint32_t
write_registry_value_binary(
    _In_ const ebpf_registry_key_t* key,
    _In_ const wchar_t* value_name,
    _In_reads_(value_size) uint8_t* value,
    _In_ size_t value_size);

uint32_t
write_registry_value_ansi_string(
    _In_ const ebpf_registry_key_t* key, _In_ const wchar_t* value_name, _In_z_ const char* value);

uint32_t
write_registry_value_dword(_In_ const ebpf_registry_key_t* key, _In_z_ const wchar_t* value_name, uint32_t value);

uint32_t
create_registry_key(
    _In_opt_ const ebpf_registry_key_t* root_key,
    _In_ const wchar_t* sub_key,
    uint32_t flags,
    _Out_ ebpf_registry_key_t* key);

uint32_t
open_registry_key(
    _In_ const ebpf_registry_key_t* root_key,
    _In_opt_z_ const wchar_t* sub_key,
    uint32_t flags,
    _Out_ ebpf_registry_key_t* key);

uint32_t
delete_registry_key(_In_ const ebpf_registry_key_t* root_key, _In_z_ const wchar_t* sub_key);

uint32_t
delete_registry_tree(_In_ const ebpf_registry_key_t* root_key, _In_opt_z_ const wchar_t* sub_key);

ebpf_result_t
read_registry_value_dword(_In_ HKEY key, _In_ const wchar_t* value_name, _Out_ uint32_t* value);

ebpf_result_t
read_registry_value_binary(
    _In_ HKEY key, _In_ const wchar_t* value_name, _Out_writes_(value_size) uint8_t* value, _In_ size_t value_size);

_Success_(return == 0) uint32_t
    convert_guid_to_string(_In_ const GUID* guid, _Out_writes_all_(string_size) wchar_t* string, size_t string_size);

uint32_t
create_registry_key_ansi(
    _In_ const ebpf_registry_key_t* root_key,
    _In_z_ const char* sub_key,
    uint32_t flags,
    _Out_ ebpf_registry_key_t* key);

ebpf_result_t
read_registry_value_string(HKEY key, _In_ const wchar_t* value_name, _Out_ wchar_t** value);