// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <Windows.h>
#include <functional>
#include <io.h>

extern std::function<decltype(_close)> close_handler;
extern std::function<decltype(CancelIoEx)> cancel_io_ex_handler;
extern std::function<decltype(CloseHandle)> close_handle_handler;
extern std::function<decltype(CreateFileW)> create_file_handler;
extern std::function<decltype(DuplicateHandle)> duplicate_handle_handler;
extern std::function<decltype(DeviceIoControl)> device_io_control_handler;
extern std::function<decltype(_get_osfhandle)> get_osfhandle_handler;
extern std::function<decltype(_open_osfhandle)> open_osfhandle_handler;
