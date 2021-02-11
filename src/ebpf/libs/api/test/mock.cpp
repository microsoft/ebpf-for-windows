/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/

#include "mock.h"
std::function<decltype(CreateFileW)> create_file_handler;
std::function<decltype(DeviceIoControl)> device_io_control_handler;
std::function<decltype(CloseHandle)> close_handle_handler;

namespace Platform {
    BOOL
        DeviceIoControl(
            _In_ HANDLE hDevice,
            _In_ DWORD dwIoControlCode,
            _In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
            _In_ DWORD nInBufferSize,
            _Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
            _In_ DWORD nOutBufferSize,
            _Out_opt_ LPDWORD lpBytesReturned,
            _Inout_opt_ LPOVERLAPPED lpOverlapped
        )
    {
        return device_io_control_handler(
            hDevice,
            dwIoControlCode,
            lpInBuffer,
            nInBufferSize,
            lpOutBuffer,
            nOutBufferSize,
            lpBytesReturned,
            lpOverlapped);
    }

    HANDLE
        CreateFileW(
            _In_ LPCWSTR lpFileName,
            _In_ DWORD dwDesiredAccess,
            _In_ DWORD dwShareMode,
            _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            _In_ DWORD dwCreationDisposition,
            _In_ DWORD dwFlagsAndAttributes,
            _In_opt_ HANDLE hTemplateFile
        )
    {
        return create_file_handler(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile);
    }
    BOOL
        CloseHandle(
            _In_ _Post_ptr_invalid_ HANDLE hObject
        )
    {
        return close_handle_handler(hObject);
    }

}