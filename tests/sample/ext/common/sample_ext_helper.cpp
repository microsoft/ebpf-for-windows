// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "sample_ext_helper.h"

#include <cstdio>
#include <cstring>

_sample_extension_helper::_sample_extension_helper(bool log_invoke_errors)
    : _device_handle(INVALID_HANDLE_VALUE), _log_invoke_errors(log_invoke_errors)
{
    _device_handle = ::CreateFileW(
        SAMPLE_EBPF_EXT_DEVICE_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
}

_sample_extension_helper::~_sample_extension_helper()
{
    if (_device_handle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(_device_handle);
    }
}

bool
_sample_extension_helper::invoke(std::vector<char>& input_buffer, std::vector<char>& output_buffer)
{
    if (_device_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    uint32_t count_of_bytes_returned;
    return (
        ::DeviceIoControl(
            _device_handle,
            IOCTL_SAMPLE_EBPF_EXT_CTL_RUN,
            input_buffer.data(),
            static_cast<uint32_t>(input_buffer.size()),
            output_buffer.data(),
            static_cast<uint32_t>(output_buffer.size()),
            (unsigned long*)&count_of_bytes_returned,
            nullptr) == TRUE);
}

bool
_sample_extension_helper::invoke_by_attach_parameter(
    const void* attach_parameter,
    size_t attach_parameter_size,
    std::vector<char>& input_buffer,
    std::vector<char>& output_buffer)
{
    return try_invoke_by_attach_parameter(attach_parameter, attach_parameter_size, input_buffer, output_buffer);
}

bool
_sample_extension_helper::try_invoke_by_attach_parameter(
    const void* attach_parameter,
    size_t attach_parameter_size,
    std::vector<char>& input_buffer,
    std::vector<char>& output_buffer)
{
    if (_device_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    uint32_t count_of_bytes_returned;
    size_t request_size =
        FIELD_OFFSET(sample_ebpf_ext_run_request_t, data) + attach_parameter_size + input_buffer.size();
    std::vector<uint8_t> request_buffer(request_size);
    sample_ebpf_ext_run_request_t* request = (sample_ebpf_ext_run_request_t*)request_buffer.data();
    request->version = SAMPLE_EBPF_EXT_RUN_REQUEST_VERSION;
    request->attach_parameter_size = static_cast<uint32_t>(attach_parameter_size);
    request->program_data_size = static_cast<uint32_t>(input_buffer.size());
    memcpy(request->data, attach_parameter, attach_parameter_size);
    memcpy(request->data + attach_parameter_size, input_buffer.data(), input_buffer.size());

    BOOL success = ::DeviceIoControl(
        _device_handle,
        IOCTL_SAMPLE_EBPF_EXT_CTL_RUN,
        request_buffer.data(),
        static_cast<uint32_t>(request_buffer.size()),
        output_buffer.data(),
        static_cast<uint32_t>(output_buffer.size()),
        (unsigned long*)&count_of_bytes_returned,
        nullptr);
    if (success != TRUE && _log_invoke_errors) {
        printf("DeviceIoControl(IOCTL_SAMPLE_EBPF_EXT_CTL_RUN) failed: %lu\n", GetLastError());
    }
    return success == TRUE;
}

bool
_sample_extension_helper::invoke_batch(std::vector<char>& input_buffer, std::vector<char>& output_buffer)
{
    if (_device_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    uint32_t count_of_bytes_returned;
    return (
        ::DeviceIoControl(
            _device_handle,
            IOCTL_SAMPLE_EBPF_EXT_CTL_RUN_BATCH,
            input_buffer.data(),
            static_cast<uint32_t>(input_buffer.size()),
            output_buffer.data(),
            static_cast<uint32_t>(output_buffer.size()),
            (unsigned long*)&count_of_bytes_returned,
            nullptr) == TRUE);
}
