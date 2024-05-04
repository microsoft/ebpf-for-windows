// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_store_helper.h"

#define REG_CREATE_FLAGS (KEY_WRITE | DELETE | KEY_READ)
#define REG_OPEN_FLAGS (DELETE | KEY_READ)
#define REG_DELETE_FLAGS (DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE)

#ifdef __cplusplus
extern "C"
{
#endif

    wchar_t*
    ebpf_get_wstring_from_string(_In_ const char* text);

    void
    ebpf_free_wstring(_Frees_ptr_opt_ wchar_t* text);

    void
    ebpf_close_registry_key(ebpf_store_key_t key);

    _Must_inspect_result_ ebpf_result_t
    ebpf_write_registry_value_binary(
        ebpf_store_key_t key,
        _In_z_ const wchar_t* value_name,
        _In_reads_(value_size) uint8_t* value,
        size_t value_size);

    _Must_inspect_result_ ebpf_result_t
    ebpf_write_registry_value_string(
        ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _In_z_ const wchar_t* value);

    _Must_inspect_result_ ebpf_result_t
    ebpf_write_registry_value_dword(ebpf_store_key_t key, _In_z_ const wchar_t* value_name, uint32_t value);

    _Must_inspect_result_ ebpf_result_t
    ebpf_create_registry_key(
        ebpf_store_key_t root_key, _In_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_store_key_t* key);

    _Must_inspect_result_ ebpf_result_t
    ebpf_open_registry_key(
        ebpf_store_key_t root_key, _In_opt_z_ const wchar_t* sub_key, uint32_t flags, _Out_ ebpf_store_key_t* key);

    _Must_inspect_result_ ebpf_result_t
    ebpf_delete_registry_key(ebpf_store_key_t root_key, _In_z_ const wchar_t* sub_key);

    _Must_inspect_result_ ebpf_result_t
    ebpf_delete_registry_tree(ebpf_store_key_t root_key, _In_opt_z_ const wchar_t* sub_key);

    _Must_inspect_result_ ebpf_result_t
    ebpf_read_registry_value_dword(ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _Out_ uint32_t* value);

    _Must_inspect_result_ ebpf_result_t
    ebpf_read_registry_value_binary(
        ebpf_store_key_t key,
        _In_z_ const wchar_t* value_name,
        _Out_writes_(value_size) uint8_t* value,
        size_t value_size);

    _Must_inspect_result_ ebpf_result_t
    ebpf_convert_guid_to_string(
        _In_ const GUID* guid, _Out_writes_all_(string_size) wchar_t* string, size_t string_size);

    _Must_inspect_result_ ebpf_result_t
    ebpf_convert_string_to_guid(_In_z_ const wchar_t* string, _Out_ GUID* guid);

    _Must_inspect_result_ ebpf_result_t
    ebpf_read_registry_value_string(
        ebpf_store_key_t key, _In_z_ const wchar_t* value_name, _Outptr_result_maybenull_ wchar_t** value);

#ifdef __cplusplus
}
#endif
