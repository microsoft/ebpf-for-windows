// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_core_structs.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma once
namespace Platform {
bool
DeviceIoControl(
    _In_ ebpf_handle_t device_handle,
    uint32_t io_control_code,
    _In_reads_bytes_opt_(input_buffer_size) void* input_buffer,
    uint32_t input_buffer_size,
    _Out_writes_bytes_to_opt_(output_buffer_size, *count_of_bytes_returned) void* output_buffer,
    uint32_t output_buffer_size,
    _Out_opt_ uint32_t* count_of_bytes_returned,
    _Inout_opt_ OVERLAPPED* overlapped);

bool
CancelIoEx(_In_ ebpf_handle_t device_handle, _In_opt_ OVERLAPPED* overlapped);

ebpf_handle_t
CreateFileW(
    _In_ PCWSTR file_name,
    uint32_t desired_access,
    uint32_t share_mode,
    _In_opt_ SECURITY_ATTRIBUTES* security_attributes,
    uint32_t creation_disposition,
    uint32_t flags_and_attributes,
    _In_opt_ ebpf_handle_t template_file);

bool
CloseHandle(_In_ _Post_ptr_invalid_ ebpf_handle_t handle);

bool
DuplicateHandle(
    _In_ ebpf_handle_t source_process_handle,
    _In_ ebpf_handle_t source_handle,
    _In_ ebpf_handle_t target_process_handle,
    _Out_ ebpf_handle_t* target_handle,
    uint32_t desired_access,
    bool inherit_handle,
    uint32_t options);

int
_open_osfhandle(intptr_t os_file_handle, int flags);

intptr_t
_get_osfhandle(int file_descriptor);

int
_close(int file_descriptor);

int
_dup(int file_descriptor);

bool
_is_native_program(_In_z_ const char* file_name);

uint32_t
_create_registry_key(HKEY root_key, _In_z_ const wchar_t* path);

uint32_t
_update_registry_value(
    HKEY root_key,
    _In_z_ const wchar_t* sub_key,
    unsigned long type,
    _In_z_ const wchar_t* value_name,
    _In_reads_bytes_(value_size) const void* value,
    uint32_t value_size);

uint32_t
_create_service(_In_z_ const wchar_t* service_name, _In_z_ const wchar_t* file_path, _Out_ SC_HANDLE* service_handle);

uint32_t
_delete_service(SC_HANDLE service_handle);

uint32_t
_stop_service(SC_HANDLE service_handle);

bool
_query_service_status(SC_HANDLE service_handle, _Inout_ SERVICE_STATUS* status);

} // namespace Platform
