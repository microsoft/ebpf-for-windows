// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once
#include <Windows.h>
#include <functional>
#include <io.h>

uint32_t
_create_service(_In_z_ const wchar_t* service_name, _In_z_ const wchar_t* file_path, _Out_ SC_HANDLE* service_handle);

uint32_t
_delete_service(SC_HANDLE service_handle);

uint32_t
_get_service(_In_z_ const wchar_t* service_name, _Out_ SC_HANDLE* service_handle);

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
_get_registry_value(
    HKEY root_key,
    _In_z_ const wchar_t* sub_key,
    unsigned long type,
    _In_z_ const wchar_t* value_name,
    _Out_writes_bytes_opt_(*value_size) uint8_t* value,
    _Inout_opt_ uint32_t* value_size);

extern std::function<decltype(_close)> close_handler;
extern std::function<decltype(CancelIoEx)> cancel_io_ex_handler;
extern std::function<decltype(CloseHandle)> close_handle_handler;
extern std::function<decltype(CreateFileW)> create_file_handler;
extern std::function<decltype(DuplicateHandle)> duplicate_handle_handler;
extern std::function<decltype(DeviceIoControl)> device_io_control_handler;
extern std::function<decltype(_get_osfhandle)> get_osfhandle_handler;
extern std::function<decltype(_open_osfhandle)> open_osfhandle_handler;
extern std::function<decltype(_create_service)> create_service_handler;
extern std::function<decltype(_delete_service)> delete_service_handler;
extern std::function<decltype(_get_service)> get_service_handler;
extern std::function<decltype(_create_registry_key)> create_registry_key_handler;
extern std::function<decltype(_update_registry_value)> update_registry_value_handler;
extern std::function<decltype(_get_registry_value)> get_registry_value_handler;
