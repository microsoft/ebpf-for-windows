/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#pragma once
namespace Platform
{
        BOOL
        DeviceIoControl(
            _In_ HANDLE device_handle,
            uint32_t io_control_code,
            _In_reads_bytes_opt_(input_buffer_size) void* input_buffer,
            uint32_t input_buffer_size,
            _Out_writes_bytes_to_opt_(output_buffer_size, *count_of_bytes_returned) void* output_buffer,
            uint32_t output_buffer_size,
            _Out_opt_ uint32_t* count_of_bytes_returned,
            _Inout_opt_ OVERLAPPED* overlapped
        );

        HANDLE
        CreateFileW(
            _In_ PCWSTR file_name,
            uint32_t desired_access,
            uint32_t share_mode,
            _In_opt_ SECURITY_ATTRIBUTES* security_attributed,
            uint32_t creation_disposition,
            uint32_t flags_and_attributed,
            _In_opt_ HANDLE template_file
        );

        BOOL
        CloseHandle(
            _In_ _Post_ptr_invalid_ HANDLE handle
        );
}
