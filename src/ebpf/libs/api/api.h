/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#pragma once
#include "../../include/ebpf_windows.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(EBPF_API)
#define DLL __declspec(dllexport)
#else
#define DLL __declspec(dllimport)
#endif

    DLL DWORD ebpf_api_initiate();

    DLL void ebpf_api_terminate();

    DLL DWORD ebpf_api_load_program(const char* file, const char* section_name, HANDLE* handle, char** error_message);
    DLL void ebpf_api_free_error_message(char* error_message);
    DLL void ebpf_api_unload_program(HANDLE handle);

    DLL DWORD ebpf_api_attach_program(HANDLE handle, ebpf_program_type_t hook_point);
    DLL DWORD ebpf_api_detach_program(HANDLE handle, ebpf_program_type_t hook_point);

    DLL DWORD ebpf_api_map_lookup_element(HANDLE handle, DWORD key_size, unsigned char* key, DWORD value_size, unsigned char* value);
    DLL DWORD ebpf_api_map_update_element(HANDLE handle, DWORD key_size, unsigned char* key, DWORD value_size, unsigned char* value);
    DLL DWORD ebpf_api_map_delete_element(HANDLE handle, DWORD key_size, unsigned char* key);

    DLL DWORD ebpf_api_map_enumerate(HANDLE previous_handle, HANDLE* next_handle);
    DLL DWORD ebpf_api_map_query_definition(HANDLE handle, DWORD* size, DWORD* type, DWORD* key_size, DWORD* value_size, DWORD* max_entries);

    DLL void ebpf_api_delete_map(HANDLE handle);

#ifdef __cplusplus
}
#endif
