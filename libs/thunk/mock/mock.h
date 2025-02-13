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

extern std::function<decltype(_close)> close_handler;
extern std::function<decltype(_dup)> dup_handler;
extern std::function<decltype(CancelIoEx)> cancel_io_ex_handler;
extern std::function<decltype(CloseHandle)> close_handle_handler;
extern std::function<decltype(CreateFileW)> create_file_handler;
extern std::function<decltype(DuplicateHandle)> duplicate_handle_handler;
extern std::function<decltype(DeviceIoControl)> device_io_control_handler;
extern std::function<decltype(_get_osfhandle)> get_osfhandle_handler;
extern std::function<decltype(_open_osfhandle)> open_osfhandle_handler;
extern std::function<decltype(_create_service)> create_service_handler;
extern std::function<decltype(_delete_service)> delete_service_handler;
