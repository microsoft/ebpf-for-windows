// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <winioctl.h>
#include "catch_wrapper.hpp"
#include "sample_ext_ioctls.h"

typedef struct _sample_extension_helper
{
  public:
    _sample_extension_helper() : device_handle(INVALID_HANDLE_VALUE)
    {
        // Open handle to test eBPF extension device.
        REQUIRE(
            (device_handle = ::CreateFileW(
                 SAMPLE_EBPF_EXT_DEVICE_WIN32_NAME,
                 GENERIC_READ | GENERIC_WRITE,
                 0,
                 nullptr,
                 CREATE_ALWAYS,
                 FILE_ATTRIBUTE_NORMAL,
                 nullptr)) != INVALID_HANDLE_VALUE);
    }

    ~_sample_extension_helper()
    {
        if (device_handle != INVALID_HANDLE_VALUE)
            ::CloseHandle(device_handle);
    }

    void
    invoke(std::vector<char>& input_buffer, std::vector<char>& output_buffer)
    {
        uint32_t count_of_bytes_returned;

        // Issue IOCTL.
        REQUIRE(
            ::DeviceIoControl(
                device_handle,
                IOCTL_SAMPLE_EBPF_EXT_CTL_RUN,
                input_buffer.data(),
                static_cast<uint32_t>(input_buffer.size()),
                output_buffer.data(),
                static_cast<uint32_t>(output_buffer.size()),
                (DWORD*)&count_of_bytes_returned,
                nullptr) == TRUE);
    }

    uint64_t
    invoke_profile(std::vector<char>& input_buffer, uint64_t iterations, uint64_t flags)
    {
        std::vector<uint8_t*> request_buffer(input_buffer.size() + offsetof(sample_ebpf_ext_profile_request_t, data));
        auto request = reinterpret_cast<sample_ebpf_ext_profile_request_t*>(request_buffer.data());
        sample_ebpf_ext_profile_reply_t reply;

        std::copy(input_buffer.begin(), input_buffer.end(), reinterpret_cast<char*>(request->data));
        request->iterations = iterations;
        request->flags = flags;
        uint32_t count_of_bytes_returned;
        REQUIRE(
            ::DeviceIoControl(
                device_handle,
                IOCTL_SAMPLE_EBPF_EXT_CTL_RUN,
                request_buffer.data(),
                static_cast<uint32_t>(request_buffer.size()),
                &reply,
                static_cast<uint32_t>(sizeof(reply)),
                (DWORD*)&count_of_bytes_returned,
                nullptr) == TRUE);
        return reply.duration;
    }

  private:
    HANDLE device_handle;
} sample_extension_helper_t;
