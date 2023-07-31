// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_store_helper.h"

#define REG_CREATE_FLAGS 0

ebpf_result_t
convert_guid_to_string(_In_ const GUID* guid, _Out_writes_all_(string_length) wchar_t* string, size_t string_length);

void
close_registry_key(ebpf_store_key_t key);

_Must_inspect_result_ ebpf_result_t
write_registry_value_binary(
    ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _In_reads_(value_size) uint8_t* value, size_t value_size);

_Must_inspect_result_ ebpf_result_t
write_registry_value_ansi_string(ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _In_z_ const char* value);

_Must_inspect_result_ ebpf_result_t
write_registry_value_dword(ebpf_store_key_t key, _In_z_ const wchar_t* value_name, uint32_t value);

_Must_inspect_result_ ebpf_result_t
create_registry_key(
    ebpf_store_key_t root_key, _In_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_store_key_t* key);

_Must_inspect_result_ ebpf_result_t
create_registry_key_ansi(
    ebpf_store_key_t root_key, _In_z_ const char* sub_key, uint32_t flags, _Out_ ebpf_store_key_t* key);