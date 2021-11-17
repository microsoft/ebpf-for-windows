// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_service.h"
#include "ebpf_api.h"
#include "mock.h"
#include "rpc_interface_h.h"

std::function<decltype(_close)> close_handler;
std::function<decltype(CancelIoEx)> cancel_io_ex_handler;
std::function<decltype(CloseHandle)> close_handle_handler;
std::function<decltype(CreateFileW)> create_file_handler;
std::function<decltype(DuplicateHandle)> duplicate_handle_handler;
std::function<decltype(DeviceIoControl)> device_io_control_handler;
std::function<decltype(_get_osfhandle)> get_osfhandle_handler;
std::function<decltype(_open_osfhandle)> open_osfhandle_handler;

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
    return device_io_control_handler(
        reinterpret_cast<HANDLE>(device_handle),
        (DWORD)io_control_code,
        input_buffer,
        (DWORD)input_buffer_size,
        output_buffer,
        (DWORD)output_buffer_size,
        (DWORD*)count_of_bytes_returned,
        overlapped);
}

bool
CancelIoEx(_In_ ebpf_handle_t device_handle, _In_opt_ OVERLAPPED* overlapped)
{
    return cancel_io_ex_handler(reinterpret_cast<HANDLE>(device_handle), overlapped);
}

ebpf_handle_t
CreateFileW(
    _In_ PCWSTR file_name,
    uint32_t desired_access,
    uint32_t share_mode,
    _In_opt_ SECURITY_ATTRIBUTES* security_attributes,
    uint32_t creation_disposition,
    uint32_t flags_and_attributes,
    _In_opt_ ebpf_handle_t template_file)
{
    return reinterpret_cast<ebpf_handle_t>(create_file_handler(
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
    return close_handle_handler(reinterpret_cast<HANDLE>(handle));
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
    return duplicate_handle_handler(
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
    return open_osfhandle_handler(os_file_handle, flags);
}

intptr_t
_get_osfhandle(int file_descriptor)
{
    return get_osfhandle_handler(file_descriptor);
}

int
_close(int file_handle)
{
    return close_handler(file_handle);
}

} // namespace Platform

// RPC related mock functions.

RPC_STATUS
initialize_rpc_binding() { return RPC_S_OK; }

RPC_STATUS
clean_up_rpc_binding() { return RPC_S_OK; }

ebpf_result_t
ebpf_rpc_load_program(ebpf_program_load_info* info, const char** logs, uint32_t* logs_size)
{
    // Set the handle of program being verified in thread-local storage.
    set_program_under_verification(reinterpret_cast<ebpf_handle_t>(info->program_handle));

    // Short circuit rpc call to service lib.
    ebpf_result_t result = ebpf_verify_and_load_program(
        &info->program_type,
        reinterpret_cast<ebpf_handle_t>(info->program_handle),
        info->execution_context,
        info->execution_type,
        info->map_count,
        info->handle_map,
        info->byte_code_size,
        info->byte_code,
        const_cast<const char**>(logs),
        logs_size);

    ebpf_clear_thread_local_storage();
    return result;
}
