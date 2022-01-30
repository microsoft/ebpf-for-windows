// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <chrono>
#include <future>
#include <map>
using namespace std::chrono_literals;

#include "bpf/bpf.h"
#include "catch_wrapper.hpp"
#include "api_internal.h"
#include "ebpf_async.h"
#include "ebpf_core.h"
#include "helpers.h"
#include "mock.h"
#include "test_helper.hpp"

static uint64_t _ebpf_file_descriptor_counter = 0;
static std::map<fd_t, ebpf_handle_t> _fd_to_handle_map;

class duplicate_handles_table_t
{
  public:
    duplicate_handles_table_t() : _rundown_in_progress(false), _all_duplicate_handles_closed(nullptr)
    {
        ebpf_lock_create(&_lock);
    }
    ~duplicate_handles_table_t() { ebpf_lock_destroy(&_lock); }

    bool
    reference_or_add(ebpf_handle_t handle)
    {
        bool success = true;
        auto state = ebpf_lock_lock(&_lock);
        if (!_rundown_in_progress) {
            std::map<ebpf_handle_t, uint16_t>::iterator it = _duplicate_count_table.find(handle);
            if (it != _duplicate_count_table.end()) {
                it->second++;
            } else {
                try {
                    // The reference count of newly inserted duplicate handle is 2 (for original + first duplicate).
                    _duplicate_count_table.insert(std::pair<ebpf_handle_t, uint16_t>(handle, static_cast<uint16_t>(2)));
                } catch (...) {
                    success = false;
                }
            }
        }
        ebpf_lock_unlock(&_lock, state);
        return success;
    }

    bool
    dereference_if_found(ebpf_handle_t handle)
    {
        bool found = false;

        auto state = ebpf_lock_lock(&_lock);
        std::map<ebpf_handle_t, uint16_t>::iterator it = _duplicate_count_table.find(handle);
        if (it != _duplicate_count_table.end()) {
            found = true;
            // Dereference the handle. If the reference count drops to 0, close the handle.
            if (--it->second == 0) {
                _duplicate_count_table.erase(handle);
                ebpf_api_close_handle(handle);
            }
            if (_rundown_in_progress && _duplicate_count_table.size() == 0) {
                // All duplicate handles have been closed. Fulfill the promise.
                REQUIRE(_all_duplicate_handles_closed != nullptr);
                _all_duplicate_handles_closed->set_value();
            }
        }

        ebpf_lock_unlock(&_lock, state);
        return found;
    }

    void
    rundown()
    {
        auto state = ebpf_lock_lock(&_lock);
        std::future<void> all_duplicate_handles_closed_callback;
        bool duplicates_pending = false;
        if (_duplicate_count_table.size() > 0) {
            duplicates_pending = true;
            _all_duplicate_handles_closed = new (std::nothrow) std::promise<void>();
            REQUIRE(_all_duplicate_handles_closed != nullptr);
            all_duplicate_handles_closed_callback = _all_duplicate_handles_closed->get_future();
            _rundown_in_progress = true;
        }
        ebpf_lock_unlock(&_lock, state);
        if (duplicates_pending)
            // Wait for at most 1 second for all duplicate handles to be closed.
            REQUIRE(all_duplicate_handles_closed_callback.wait_for(1s) == std::future_status::ready);

        state = ebpf_lock_lock(&_lock);
        _rundown_in_progress = false;
        delete _all_duplicate_handles_closed;
        _all_duplicate_handles_closed = nullptr;
        ebpf_lock_unlock(&_lock, state);
    }

  private:
    ebpf_lock_t _lock;
    // Map of handles to duplicate count.
    std::map<ebpf_handle_t, uint16_t> _duplicate_count_table;
    bool _rundown_in_progress;
    std::promise<void>* _all_duplicate_handles_closed;
};

static duplicate_handles_table_t _duplicate_handles;

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
    _duplicate_handles.dereference_if_found(reinterpret_cast<ebpf_handle_t>(hObject));

    return TRUE;
}

BOOL
GlueDuplicateHandle(
    HANDLE hSourceProcessHandle,
    HANDLE hSourceHandle,
    HANDLE hTargetProcessHandle,
    LPHANDLE lpTargetHandle,
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwOptions)
{
    UNREFERENCED_PARAMETER(hSourceProcessHandle);
    UNREFERENCED_PARAMETER(hTargetProcessHandle);
    UNREFERENCED_PARAMETER(dwDesiredAccess);
    UNREFERENCED_PARAMETER(bInheritHandle);
    UNREFERENCED_PARAMETER(dwOptions);
    // Return the same value for duplicated handle.
    *lpTargetHandle = hSourceHandle;
    return !!_duplicate_handles.reference_or_add(reinterpret_cast<ebpf_handle_t>(hSourceHandle));
}

static void
_complete_overlapped(void* context, size_t output_buffer_length, ebpf_result_t result)
{
    UNREFERENCED_PARAMETER(output_buffer_length);
    auto overlapped = reinterpret_cast<OVERLAPPED*>(context);
    overlapped->Internal = ebpf_result_to_ntstatus(result);
    SetEvent(overlapped->hEvent);
}

BOOL
GlueCancelIoEx(_In_ HANDLE hFile, _In_opt_ LPOVERLAPPED lpOverlapped)
{
    UNREFERENCED_PARAMETER(hFile);
    BOOL return_value = FALSE;
    if (lpOverlapped != nullptr)
        return_value = ebpf_core_cancel_protocol_handler(lpOverlapped);
    return return_value;
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
        SetLastError(ebpf_result_to_win32_error_code(result));
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
        bool found = _duplicate_handles.dereference_if_found(it->second);
        if (!found)
            // No duplicates. Close the handle.
            ebpf_api_close_handle(it->second);
        _fd_to_handle_map.erase(file_descriptor);
        return 0;
    }
}

_test_helper_end_to_end::_test_helper_end_to_end()
{
    device_io_control_handler = GlueDeviceIoControl;
    cancel_io_ex_handler = GlueCancelIoEx;
    create_file_handler = GlueCreateFileW;
    close_handle_handler = GlueCloseHandle;
    duplicate_handle_handler = GlueDuplicateHandle;
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
    // Run down duplicate handles, if any.
    _duplicate_handles.rundown();
    // Verify that all maps were successfully removed.
    uint32_t id;
    REQUIRE(bpf_map_get_next_id(0, &id) < 0);
    REQUIRE(errno == ENOENT);

    if (api_initialized)
        ebpf_api_terminate();
    if (ec_initialized)
        ebpf_core_terminate();

    device_io_control_handler = nullptr;
    cancel_io_ex_handler = nullptr;
    create_file_handler = nullptr;
    close_handle_handler = nullptr;
    duplicate_handle_handler = nullptr;
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
