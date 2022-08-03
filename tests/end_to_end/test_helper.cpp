// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <chrono>
#include <filesystem>
#include <future>
#include <map>
using namespace std::chrono_literals;

#include "bpf/bpf.h"
#include "catch_wrapper.hpp"
#include "api_common.hpp"
#include "api_internal.h"
#include "bpf2c.h"
#include "ebpf_async.h"
#include "ebpf_core.h"
#include "ebpf_platform.h"
#include "helpers.h"
#include "mock.h"
#include "test_helper.hpp"

extern "C" bool ebpf_fuzzing_enabled;
extern bool _ebpf_platform_is_preemptible;

static bool _is_platform_preemptible = false;

extern "C" metadata_table_t*
get_metadata_table();

static bool _expect_native_module_load_failures = false;

#define SERVICE_PATH_PREFIX L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"

static GUID _bpf2c_npi_id = {/* c847aac8-a6f2-4b53-aea3-f4a94b9a80cb */
                             0xc847aac8,
                             0xa6f2,
                             0x4b53,
                             {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};

static GUID _ebpf_native_provider_id = {/* 5e24d2f5-f799-42c3-a945-87feefd930a7 */
                                        0x5e24d2f5,
                                        0xf799,
                                        0x42c3,
                                        {0xa9, 0x45, 0x87, 0xfe, 0xef, 0xd9, 0x30, 0xa7}};

typedef struct _service_context
{
    std::wstring name;
    std::wstring file_path;
    intptr_t handle{};
    GUID module_id{};
    HMODULE dll;
    bool loaded;
    ebpf_extension_client_t* binding_context;
    bool delete_pending = false;
} service_context_t;

static uint64_t _ebpf_file_descriptor_counter = 0;
static std::map<fd_t, ebpf_handle_t> _fd_to_handle_map;

static uint32_t _ebpf_service_handle_counter = 0;
static std::map<std::wstring, service_context_t*> _service_path_to_context_map;

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

#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory 'context'
static void
_unload_all_native_modules()
{
    for (auto& [path, context] : _service_path_to_context_map) {
        if (context->loaded) {
            // Deregister client.
            ebpf_extension_unload(context->binding_context);
        }
        // The service should have been marked for deletion till now.
        REQUIRE((context->delete_pending || _expect_native_module_load_failures));
        if (context->dll != nullptr) {
            FreeLibrary(context->dll);
        }
        ebpf_free(context);
    }
    _service_path_to_context_map.clear();
}
#pragma warning(pop)

static void
_preprocess_load_native_module(_Inout_ service_context_t* context)
{
    // Every time a native module is loaded, flip the bit for _ebpf_platform_is_preemptible.
    // This ensures both the code paths are executed in the native module code, when the
    // test cases are executed.
    _ebpf_platform_is_preemptible = _is_platform_preemptible;
    _is_platform_preemptible = !_is_platform_preemptible;

    context->dll = LoadLibraryW(context->file_path.c_str());
    REQUIRE(((context->dll != nullptr) || (_expect_native_module_load_failures)));

    if (context->dll == nullptr) {
        return;
    }

    auto get_function =
        reinterpret_cast<decltype(&get_metadata_table)>(GetProcAddress(context->dll, "get_metadata_table"));
    if (get_function == nullptr) {
        REQUIRE(_expect_native_module_load_failures);
        return;
    }

    metadata_table_t* table = get_function();
    REQUIRE(table != nullptr);

    int client_binding_context = 0;
    void* provider_binding_context = nullptr;
    const ebpf_extension_data_t* returned_provider_data;
    const ebpf_extension_dispatch_table_t* returned_provider_dispatch_table;

    // Register as client.
    ebpf_result_t result = ebpf_extension_load(
        &context->binding_context,
        &_bpf2c_npi_id,
        &_ebpf_native_provider_id,
        &context->module_id,
        &client_binding_context,
        (const ebpf_extension_data_t*)table,
        nullptr,
        &provider_binding_context,
        &returned_provider_data,
        &returned_provider_dispatch_table,
        nullptr);

    REQUIRE((result == EBPF_SUCCESS || _expect_native_module_load_failures));

    context->loaded = true;
}

static void
_preprocess_ioctl(_In_ const ebpf_operation_header_t* user_request)
{
    switch (user_request->id) {
    case EBPF_OPERATION_LOAD_NATIVE_MODULE: {
        try {
            const ebpf_operation_load_native_module_request_t* request =
                (ebpf_operation_load_native_module_request_t*)user_request;
            size_t service_name_length = ((uint8_t*)request) + request->header.length - (uint8_t*)request->data;
            REQUIRE(((service_name_length % 2 == 0) || ebpf_fuzzing_enabled));

            std::wstring service_path;
            service_path.assign((wchar_t*)request->data, service_name_length / 2);
            auto context = _service_path_to_context_map.find(service_path);
            if (context != _service_path_to_context_map.end()) {
                context->second->module_id = request->module_id;

                if (context->second->loaded) {
                    REQUIRE(_expect_native_module_load_failures);
                } else {
                    _preprocess_load_native_module(context->second);
                }
            }
        } catch (...) {
            // Ignore.
        }
        break;
    }
    default:
        break;
    }
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
    UNREFERENCED_PARAMETER(dwIoControlCode);

    ebpf_result_t result;
    const ebpf_operation_header_t* user_request = reinterpret_cast<decltype(user_request)>(lpInBuffer);
    ebpf_operation_header_t* user_reply = nullptr;
    *lpBytesReturned = 0;
    auto request_id = user_request->id;
    size_t minimum_request_size = 0;
    size_t minimum_reply_size = 0;
    bool async = false;
    DWORD sharedBufferSize = (nInBufferSize > nOutBufferSize) ? nInBufferSize : nOutBufferSize;
    std::vector<uint8_t> sharedBuffer;
    const void* input_buffer = nullptr;
    void* output_buffer = nullptr;

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
    }

    // Intercept the call to perform any IOCTL specific _pre_ tasks.
    _preprocess_ioctl(user_request);

    if (!async) {
        // In the kernel execution context, the request and reply share
        // the same memory.  So to catch bugs that only show up in that
        // case, we force the same here.
        sharedBuffer.resize(sharedBufferSize);
        memcpy(sharedBuffer.data(), user_request, nInBufferSize);
        input_buffer = sharedBuffer.data();
        output_buffer = (minimum_reply_size > 0) ? sharedBuffer.data() : nullptr;
    } else {
        input_buffer = user_request;
        output_buffer = user_reply;
    }

    result = ebpf_core_invoke_protocol_handler(
        request_id,
        input_buffer,
        static_cast<uint16_t>(nInBufferSize),
        output_buffer,
        static_cast<uint16_t>(nOutBufferSize),
        lpOverlapped,
        _complete_overlapped);

    if (!async && minimum_reply_size > 0) {
        memcpy(user_reply, sharedBuffer.data(), nOutBufferSize);
    }

    if (result != EBPF_SUCCESS)
        goto Fail;

    if (user_reply) {
        *lpBytesReturned = user_reply->length;
    }
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

uint32_t
Glue_create_service(
    _In_z_ const wchar_t* service_name, _In_z_ const wchar_t* file_path, _Out_ SC_HANDLE* service_handle)
{
    *service_handle = (SC_HANDLE)0;
    try {
        std::wstring service_path(SERVICE_PATH_PREFIX);
        service_path = service_path + service_name;

        service_context_t* context = new (std::nothrow) service_context_t();
        if (context == nullptr) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        context->name.assign(service_name);
        context->file_path.assign(file_path);

        _service_path_to_context_map.insert(std::pair<std::wstring, service_context_t*>(service_path, context));
        context->handle = InterlockedIncrement64((int64_t*)&_ebpf_service_handle_counter);

        *service_handle = (SC_HANDLE)context->handle;
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

uint32_t
Glue_delete_service(SC_HANDLE handle)
{
    for (auto& [path, context] : _service_path_to_context_map) {
        if (context->handle == (intptr_t)handle) {
            // Delete the service if it has not been loaded yet. Otherwise
            // mark it pending for delete.
            if (!context->loaded) {
                ebpf_free(context);
                _service_path_to_context_map.erase(path);
            } else {
                context->delete_pending = true;
            }
            break;
        }
    }

    return ERROR_SUCCESS;
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
    create_service_handler = Glue_create_service;
    delete_service_handler = Glue_delete_service;
    REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    ec_initialized = true;
    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);
    api_initialized = true;
}

_test_helper_end_to_end::~_test_helper_end_to_end()
{
    try {
        // Run down duplicate handles, if any.
        _duplicate_handles.rundown();
    } catch (Catch::TestFailureException&) {
    }

    // Verify that all maps were successfully removed.
    uint32_t id;
    if (!ebpf_fuzzing_enabled) {
        REQUIRE(bpf_map_get_next_id(0, &id) < 0);
        REQUIRE(errno == ENOENT);
    }

    // Detach all the native module clients.
    _unload_all_native_modules();

    if (api_initialized)
        ebpf_api_terminate();
    if (ec_initialized)
        ebpf_core_terminate();

    device_io_control_handler = nullptr;
    cancel_io_ex_handler = nullptr;
    create_file_handler = nullptr;
    close_handle_handler = nullptr;
    duplicate_handle_handler = nullptr;

    _expect_native_module_load_failures = false;

    // Change back to original value.
    _ebpf_platform_is_preemptible = true;

    set_verification_in_progress(false);
}

_test_helper_libbpf::_test_helper_libbpf()
{
    ebpf_clear_thread_local_storage();

    xdp_program_info = new program_info_provider_t(EBPF_PROGRAM_TYPE_XDP);
    xdp_hook = new single_instance_hook_t(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);

    bind_program_info = new program_info_provider_t(EBPF_PROGRAM_TYPE_BIND);
    bind_hook = new single_instance_hook_t(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    cgroup_sock_addr_program_info = new program_info_provider_t(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR);
    cgroup_inet4_connect_hook =
        new single_instance_hook_t(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT);
}

_test_helper_libbpf::~_test_helper_libbpf()
{
    delete xdp_hook;
    delete xdp_program_info;

    delete bind_hook;
    delete bind_program_info;

    delete cgroup_inet4_connect_hook;
    delete cgroup_sock_addr_program_info;
}

void
set_native_module_failures(bool expected)
{
    _expect_native_module_load_failures = expected;
}

ebpf_result_t
get_service_details_for_file(
    _In_ const std::wstring& file_path, _Out_ const wchar_t** service_name, _Out_ GUID* provider_guid)
{
    for (auto& [path, context] : _service_path_to_context_map) {
        if (context->file_path == file_path) {
            *service_name = context->name.c_str();
            *provider_guid = context->module_id;
            return EBPF_SUCCESS;
        }
    }

    return EBPF_OBJECT_NOT_FOUND;
}