// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <io.h>
#include <stdint.h>
#include <cstdlib>
#include <crtdbg.h> // For _CrtSetReportMode
#include "ebpf_api.h"

class _invalid_parameter_suppression
{
  public:
    _invalid_parameter_suppression()
    {
        _CrtSetReportMode(_CRT_ASSERT, 0);
        previous_handler = _set_invalid_parameter_handler(_ignore_invalid_parameter);
    }
    ~_invalid_parameter_suppression() { _set_invalid_parameter_handler(previous_handler); }

  private:
    static void
    _ignore_invalid_parameter(
        const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved)
    {
        UNREFERENCED_PARAMETER(expression);
        UNREFERENCED_PARAMETER(function);
        UNREFERENCED_PARAMETER(file);
        UNREFERENCED_PARAMETER(line);
        UNREFERENCED_PARAMETER(pReserved);
    }
    _invalid_parameter_handler previous_handler;
};

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
    _Inout_opt_ OVERLAPPED* overlapped)
{
    return ::DeviceIoControl(
        reinterpret_cast<HANDLE>(device_handle),
        io_control_code,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        (DWORD*)count_of_bytes_returned,
        overlapped);
}

bool
CancelIoEx(_In_ ebpf_handle_t device_handle, _In_opt_ OVERLAPPED* overlapped)
{
    return ::CancelIoEx(reinterpret_cast<HANDLE>(device_handle), overlapped);
}

ebpf_handle_t
CreateFileW(
    _In_z_ PCWSTR file_name,
    uint32_t desired_access,
    uint32_t share_mode,
    _In_opt_ SECURITY_ATTRIBUTES* security_attributes,
    uint32_t creation_disposition,
    uint32_t flags_and_attributes,
    _In_opt_ ebpf_handle_t template_file)
{
    return reinterpret_cast<ebpf_handle_t>(::CreateFileW(
        file_name,
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_and_attributes,
        reinterpret_cast<HANDLE>(template_file)));
}

bool
CloseHandle(_In_ _Post_ptr_invalid_ ebpf_handle_t handle)
{
    return ::CloseHandle(reinterpret_cast<HANDLE>(handle));
}

bool
DuplicateHandle(
    _In_ ebpf_handle_t source_process_handle,
    _In_ ebpf_handle_t source_handle,
    _In_ ebpf_handle_t target_process_handle,
    _Out_ ebpf_handle_t* target_handle,
    uint32_t desired_access,
    bool inherit_handle,
    uint32_t options)
{
    return ::DuplicateHandle(
        reinterpret_cast<HANDLE>(source_process_handle),
        reinterpret_cast<HANDLE>(source_handle),
        reinterpret_cast<HANDLE>(target_process_handle),
        reinterpret_cast<LPHANDLE>(target_handle),
        desired_access,
        inherit_handle,
        options);
}

int
_open_osfhandle(intptr_t os_file_handle, int flags)
{
    _invalid_parameter_suppression suppress;
    return ::_open_osfhandle(os_file_handle, flags);
}

intptr_t
_get_osfhandle(int file_descriptor)
{
    _invalid_parameter_suppression suppress;
    return ::_get_osfhandle(file_descriptor);
}

int
_close(int file_descriptor)
{
    _invalid_parameter_suppression suppress;
    return ::_close(file_descriptor);
}
} // namespace Platform