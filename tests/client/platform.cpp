// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <io.h>
#include <stdint.h>
#include "ebpf_api.h"
#include "framework.h"

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

int
_open_osfhandle(intptr_t os_file_handle, int flags)
{
    return ::_open_osfhandle(os_file_handle, flags);
}

intptr_t
_get_osfhandle(int file_handle)
{
    if (file_handle == ebpf_fd_invalid) {
        return ebpf_handle_invalid;
    }
    return ::_get_osfhandle(file_handle);
}

int
_close(int file_handle)
{
    return ::_close(file_handle);
}
} // namespace Platform
