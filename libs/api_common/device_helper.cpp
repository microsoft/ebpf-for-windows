// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <map>
#include <stdexcept>
#include "ebpf_api.h"
#include "ebpf_bind_program_data.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "ebpf_xdp_program_data.h"
#include "platform.h"
#undef VOID
#include "platform.hpp"

ebpf_handle_t device_handle = INVALID_HANDLE_VALUE;

uint32_t
initialize_device_handle()
{
    if (device_handle != INVALID_HANDLE_VALUE) {
        return ERROR_ALREADY_INITIALIZED;
    }

    device_handle = Platform::CreateFile(
        EBPF_DEVICE_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (device_handle == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    return 0;
}

void
clean_up_device_handle()
{
    if (device_handle != INVALID_HANDLE_VALUE) {
        Platform::CloseHandle(device_handle);
        device_handle = INVALID_HANDLE_VALUE;
    }
}
