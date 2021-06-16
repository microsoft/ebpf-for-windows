// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Contains code to manage device for kernel mode execution context.

#include <map>
#include <mutex>
#include <stdexcept>
#include "api_common.hpp"
#include "ebpf_api.h"
#include "ebpf_bind_program_data.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "ebpf_xdp_program_data.h"
#include "platform.h"
#include "platform.hpp"

static ebpf_handle_t _device_handle = INVALID_HANDLE_VALUE;
static std::mutex _mutex;

ebpf_result_t
initialize_device_handle()
{
    std::scoped_lock lock(_mutex);

    if (_device_handle != INVALID_HANDLE_VALUE) {
        return EBPF_ALREADY_INITIALIZED;
    }

    _device_handle = Platform::CreateFile(
        EBPF_DEVICE_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (_device_handle == INVALID_HANDLE_VALUE) {
        return windows_error_to_ebpf_result(GetLastError());
    }

    return EBPF_SUCCESS;
}

void
clean_up_device_handle()
{
    std::scoped_lock lock(_mutex);

    if (_device_handle != INVALID_HANDLE_VALUE) {
        Platform::CloseHandle(_device_handle);
        _device_handle = INVALID_HANDLE_VALUE;
    }
}

ebpf_handle_t
get_device_handle()
{
    if (_device_handle == INVALID_HANDLE_VALUE) {
        initialize_device_handle();
    }

    return _device_handle;
}
