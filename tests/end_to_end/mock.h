// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <Windows.h>
#include <functional>

extern std::function<decltype(CreateFileW)> create_file_handler;
extern std::function<decltype(DeviceIoControl)> device_io_control_handler;
extern std::function<decltype(CloseHandle)> close_handle_handler;
