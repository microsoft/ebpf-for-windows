// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include "ebpf_api.h"
#include "ebpf_core.h"
#include "mock.h"

BOOL
GlueCloseHandle(ebpf_handle_t hObject);

ebpf_handle_t
GlueCreateFileW(
    PCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    PSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    ebpf_handle_t hTemplateFile);

BOOL
GlueDeviceIoControl(
    ebpf_handle_t hDevice,
    DWORD dwIoControlCode,
    PVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    PDWORD lpBytesReturned,
    OVERLAPPED* lpOverlapped);

class _test_helper_end_to_end
{
  public:
    _test_helper_end_to_end()
    {
        device_io_control_handler = GlueDeviceIoControl;
        create_file_handler = GlueCreateFileW;
        close_handle_handler = GlueCloseHandle;
        REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
        ec_initialized = true;
        REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);
        api_initialized = true;
    }
    ~_test_helper_end_to_end()
    {
        if (api_initialized)
            ebpf_api_terminate();
        if (ec_initialized)
            ebpf_core_terminate();

        device_io_control_handler = nullptr;
        create_file_handler = nullptr;
        close_handle_handler = nullptr;
    }

  private:
    bool ec_initialized = false;
    bool api_initialized = false;
};
