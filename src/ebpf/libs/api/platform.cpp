// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <windows.h>

namespace Platform {
    BOOL
        DeviceIoControl(
            _In_ HANDLE hDevice,
            DWORD dwIoControlCode,
            _In_reads_bytes_opt_(nInBufferSize) VOID* lpInBuffer,
            DWORD nInBufferSize,
            _Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) VOID* lpOutBuffer,
            DWORD nOutBufferSize,
            _Out_opt_ DWORD* lpBytesReturned,
            _Inout_opt_ OVERLAPPED* lpOverlapped)
    {
        return ::DeviceIoControl(
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
            _In_z_ LPCWSTR lpFileName,
            DWORD dwDesiredAccess,
            DWORD dwShareMode,
            _In_opt_ SECURITY_ATTRIBUTES* lpSecurityAttributes,
            DWORD dwCreationDisposition,
            DWORD dwFlagsAndAttributes,
            _In_opt_ HANDLE hTemplateFile)
    {
        return ::CreateFileW(
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
            _In_ _Post_ptr_invalid_ HANDLE hObject)
    {
        return ::CloseHandle(hObject);
    }
}