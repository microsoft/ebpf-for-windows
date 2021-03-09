/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "mock.h"
#include "api.h"
std::function<decltype(CreateFileW)> create_file_handler;
std::function<decltype(DeviceIoControl)> device_io_control_handler;
std::function<decltype(CloseHandle)> close_handle_handler;

namespace Platform {
BOOL DeviceIoControl(
    _In_ ebpf_handle_t device_handle, uint32_t io_control_code,
    _In_reads_bytes_opt_(input_buffer_size) void *input_buffer,
    uint32_t input_buffer_size,
    _Out_writes_bytes_to_opt_(output_buffer_size,
                              *count_of_bytes_returned) void *output_buffer,
    uint32_t output_buffer_size, _Out_opt_ uint32_t *count_of_bytes_returned,
    _Inout_opt_ OVERLAPPED *overlapped) {
  return device_io_control_handler(
      device_handle, (DWORD)io_control_code, input_buffer,
      (DWORD)input_buffer_size, output_buffer, (DWORD)output_buffer_size,
      (DWORD *)count_of_bytes_returned, overlapped);
}

ebpf_handle_t CreateFileW(_In_ PCWSTR file_name, uint32_t desired_access,
                          uint32_t share_mode,
                          _In_opt_ SECURITY_ATTRIBUTES *security_attributed,
                          uint32_t creation_disposition,
                          uint32_t flags_and_attributed,
                          _In_opt_ ebpf_handle_t template_file) {
  return create_file_handler(file_name, desired_access, share_mode,
                             security_attributed, creation_disposition,
                             flags_and_attributed, template_file);
}
BOOL CloseHandle(_In_ _Post_ptr_invalid_ ebpf_handle_t handle) {
  return close_handle_handler(handle);
}

} // namespace Platform