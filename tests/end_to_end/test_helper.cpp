// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <map>

#include "bpf/bpf.h"
#include "catch_wrapper.hpp"
#include "ebpf_api.h"
#include "ebpf_completion.h"
#include "ebpf_core.h"
#include "helpers.h"
#include "mock.h"
#include "test_helper.hpp"

static uint64_t _ebpf_file_descriptor_counter = 0;
static std::map<fd_t, ebpf_handle_t> _fd_to_handle_map;

HANDLE
GlueCreateFileW(
    PCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    PSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    UNREFERENCED_PARAMETER(lpFileName);
    UNREFERENCED_PARAMETER(dwDesiredAccess);
    UNREFERENCED_PARAMETER(dwShareMode);
    UNREFERENCED_PARAMETER(lpSecurityAttributes);
    UNREFERENCED_PARAMETER(dwCreationDisposition);
    UNREFERENCED_PARAMETER(dwFlagsAndAttributes);
    UNREFERENCED_PARAMETER(hTemplateFile);

    return (HANDLE)0x12345678;
}

BOOL
GlueCloseHandle(HANDLE hObject)
{
    UNREFERENCED_PARAMETER(hObject);
    return TRUE;
}

static void
_complete_overlapped(void* context, ebpf_result_t result)
{
    auto overlapped = reinterpret_cast<OVERLAPPED*>(context);
    overlapped->Internal = ebpf_result_to_ntstatus(result);
    SetEvent(overlapped->hEvent);
}

BOOL
GlueDeviceIoControl(
    HANDLE hDevice,
    DWORD dwIoControlCode,
    PVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    PDWORD lpBytesReturned,
    OVERLAPPED* lpOverlapped)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(nInBufferSize);
    UNREFERENCED_PARAMETER(dwIoControlCode);
    UNREFERENCED_PARAMETER(lpOverlapped);

    ebpf_result_t result;
    const ebpf_operation_header_t* user_request = reinterpret_cast<decltype(user_request)>(lpInBuffer);
    ebpf_operation_header_t* user_reply = nullptr;
    *lpBytesReturned = 0;
    auto request_id = user_request->id;
    size_t minimum_request_size = 0;
    size_t minimum_reply_size = 0;
    bool async = false;

    result = ebpf_core_get_protocol_handler_properties(request_id, &minimum_request_size, &minimum_reply_size, &async);
    if (result != EBPF_SUCCESS)
        goto Fail;

    if (user_request->length < minimum_request_size) {
        result = EBPF_INVALID_ARGUMENT;
        goto Fail;
    }

    if (minimum_reply_size > 0) {
        user_reply = reinterpret_cast<decltype(user_reply)>(lpOutBuffer);
        if (!user_reply) {
            result = EBPF_INVALID_ARGUMENT;
            goto Fail;
        }
        if (nOutBufferSize < minimum_reply_size) {
            result = EBPF_INVALID_ARGUMENT;
            goto Fail;
        }
        user_reply->length = static_cast<uint16_t>(nOutBufferSize);
        user_reply->id = user_request->id;
        *lpBytesReturned = user_reply->length;
    }

    result = ebpf_core_invoke_protocol_handler(
        request_id,
        user_request,
        user_reply,
        static_cast<uint16_t>(nOutBufferSize),
        lpOverlapped,
        _complete_overlapped);

    if (result != EBPF_SUCCESS)
        goto Fail;

    return TRUE;

Fail:
    if (result != EBPF_SUCCESS) {
        SetLastError(ebpf_result_to_win32(result));
    }

    return FALSE;
}

int
Glue_open_osfhandle(intptr_t os_file_handle, int flags)
{
    UNREFERENCED_PARAMETER(flags);
    try {
        fd_t fd = static_cast<fd_t>(InterlockedIncrement(&_ebpf_file_descriptor_counter));
        _fd_to_handle_map.insert(std::pair<fd_t, ebpf_handle_t>(fd, os_file_handle));
        return fd;
    } catch (...) {
        return ebpf_fd_invalid;
    }
}

intptr_t
Glue_get_osfhandle(int file_descriptor)
{
    if (file_descriptor == ebpf_fd_invalid) {
        errno = EINVAL;
        return ebpf_handle_invalid;
    }

    std::map<fd_t, ebpf_handle_t>::iterator it = _fd_to_handle_map.find(file_descriptor);
    if (it != _fd_to_handle_map.end()) {
        return it->second;
    }

    errno = EINVAL;
    return ebpf_handle_invalid;
}

int
Glue_close(int file_descriptor)
{
    if (file_descriptor == ebpf_fd_invalid) {
        errno = EINVAL;
        return ebpf_handle_invalid;
    }

    std::map<fd_t, ebpf_handle_t>::iterator it = _fd_to_handle_map.find(file_descriptor);
    if (it == _fd_to_handle_map.end()) {
        errno = EINVAL;
        return -1;
    } else {
        ebpf_api_close_handle(it->second);
        _fd_to_handle_map.erase(file_descriptor);
        return 0;
    }
}

_test_helper_end_to_end::_test_helper_end_to_end()
{
    device_io_control_handler = GlueDeviceIoControl;
    create_file_handler = GlueCreateFileW;
    close_handle_handler = GlueCloseHandle;
    open_osfhandle_handler = Glue_open_osfhandle;
    get_osfhandle_handler = Glue_get_osfhandle;
    close_handler = Glue_close;
    REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    ec_initialized = true;
    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);
    api_initialized = true;
}

_test_helper_end_to_end::~_test_helper_end_to_end()
{
    // Verify that all maps were successfully removed.
    uint32_t id;
    REQUIRE(bpf_map_get_next_id(0, &id) < 0);
    REQUIRE(errno == ENOENT);

    if (api_initialized)
        ebpf_api_terminate();
    if (ec_initialized)
        ebpf_core_terminate();

    device_io_control_handler = nullptr;
    create_file_handler = nullptr;
    close_handle_handler = nullptr;
}

_test_helper_libbpf::_test_helper_libbpf()
{
    xdp_program_info = new program_info_provider_t(EBPF_PROGRAM_TYPE_XDP);
    hook = new single_instance_hook_t(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
}

_test_helper_libbpf::~_test_helper_libbpf()
{
    delete hook;
    delete xdp_program_info;
}
