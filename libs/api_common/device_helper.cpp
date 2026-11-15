// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Contains code to manage device for kernel mode execution context.
 */

#include "api_common.hpp"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_program_types.h"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "ebpf_shared_framework.h"
#include "platform.h"
#include "platform.hpp"

#include <mutex>

typedef struct _async_ioctl_completion_context
{
    OVERLAPPED overlapped;
    PTP_WAIT wait;
    void* callback_context;
    async_ioctl_completion_callback_t callback;
} async_ioctl_completion_context_t;

// Handle used for synchronous calls to the driver.
static thread_local ebpf_handle_t _sync_device_handle = ebpf_handle_invalid;
static thread_local GUID _thread_namespace{};
static const GUID _default_namespace{};
static thread_local uint64_t _thread_namespace_generation;
static thread_local bool _thread_namespace_valid = true;
static thread_local bool _sync_device_bound;
static thread_local size_t _namespace_operation_depth;
static thread_local ebpf_handle_t _namespace_operation_handle = ebpf_handle_invalid;
static thread_local bool _namespace_operation_bound;
// Handle used for asynchronous calls to the driver.
static ebpf_handle_t _async_device_handle = ebpf_handle_invalid;
static std::mutex _mutex;

_Must_inspect_result_ ebpf_result_t
initialize_async_device_handle()
{
    std::scoped_lock lock(_mutex);

    if (_async_device_handle != ebpf_handle_invalid) {
        return EBPF_ALREADY_INITIALIZED;
    }

    // Open the device handle with the FILE_FLAG_OVERLAPPED flag for asynchronous calls.
    _async_device_handle = Platform::CreateFile(
        EBPF_DEVICE_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, 0);

    if (_async_device_handle == ebpf_handle_invalid) {
        return win32_error_code_to_ebpf_result(GetLastError());
    }

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
initialize_sync_device_handle()
{
    if (_sync_device_handle != ebpf_handle_invalid) {
        return EBPF_ALREADY_INITIALIZED;
    }

    // Open the device handle without the FILE_FLAG_OVERLAPPED flag for synchronous calls.
    _sync_device_handle =
        Platform::CreateFile(EBPF_DEVICE_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, 0);

    if (_sync_device_handle == ebpf_handle_invalid) {
        uint32_t error = GetLastError();
        if (error == ERROR_SUCCESS) {
            error = ERROR_INVALID_HANDLE;
            SetLastError(error);
        }
        return win32_error_code_to_ebpf_result(error);
    }
    _sync_device_bound = IsEqualGUID(_thread_namespace, _default_namespace);

    return EBPF_SUCCESS;
}

void
clean_up_async_device_handle()
{
    std::scoped_lock lock(_mutex);

    if (_async_device_handle != ebpf_handle_invalid) {
        Platform::CloseHandle(_async_device_handle);
        _async_device_handle = ebpf_handle_invalid;
    }
}

void
clean_up_sync_device_handle()
{
    if (_sync_device_handle != ebpf_handle_invalid) {
        if (_sync_device_handle != _namespace_operation_handle) {
            Platform::CloseHandle(_sync_device_handle);
        }
        _sync_device_handle = ebpf_handle_invalid;
        _sync_device_bound = false;
    }
}

ebpf_handle_t
get_sync_device_handle()
{
    if (_namespace_operation_handle != ebpf_handle_invalid) {
        return _namespace_operation_handle;
    }
    if (_sync_device_handle == ebpf_handle_invalid) {
        // Ignore failures.
        (void)initialize_sync_device_handle();
    }

    return _sync_device_handle;
}

static uint32_t
_set_file_namespace(ebpf_handle_t handle, const GUID& namespace_id) noexcept
{
    ebpf_operation_set_namespace_request_t request{{sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, namespace_id};
    uint32_t returned = 0;
    if (!Platform::DeviceIoControl(
            handle, IOCTL_EBPF_CTL_METHOD_BUFFERED, &request, sizeof(request), nullptr, 0, &returned, nullptr)) {
        uint32_t error = GetLastError();
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, DeviceIoControl);
        return error != ERROR_SUCCESS ? error : ERROR_GEN_FAILURE;
    }
    return returned == 0 ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
}

void
begin_thread_namespace_operation() noexcept
{
    ++_namespace_operation_depth;
}

void
end_thread_namespace_operation() noexcept
{
    ebpf_assert(_namespace_operation_depth != 0);
    if (--_namespace_operation_depth == 0) {
        if (_namespace_operation_handle != ebpf_handle_invalid && _namespace_operation_handle != _sync_device_handle) {
            Platform::CloseHandle(_namespace_operation_handle);
        }
        _namespace_operation_handle = ebpf_handle_invalid;
        _namespace_operation_bound = false;
    }
}

uint32_t
get_sync_device_handle_for_request(
    _In_reads_bytes_opt_(request_size) const void* request, uint32_t request_size, _Out_ ebpf_handle_t* handle)
{
    bool scoped = false;
    if (request != nullptr && request_size >= sizeof(ebpf_operation_header_t)) {
        const auto* header = static_cast<const ebpf_operation_header_t*>(request);
        switch (header->id) {
        case EBPF_OPERATION_CREATE_PROGRAM:
        case EBPF_OPERATION_CREATE_MAP:
        case EBPF_OPERATION_UPDATE_PINNING:
        case EBPF_OPERATION_UPDATE_PINNING_EX:
        case EBPF_OPERATION_GET_PINNED_OBJECT:
        case EBPF_OPERATION_LINK_PROGRAM:
        case EBPF_OPERATION_GET_LINK_HANDLE_BY_ID:
        case EBPF_OPERATION_GET_MAP_HANDLE_BY_ID:
        case EBPF_OPERATION_GET_PROGRAM_HANDLE_BY_ID:
        case EBPF_OPERATION_GET_NEXT_LINK_ID:
        case EBPF_OPERATION_GET_NEXT_MAP_ID:
        case EBPF_OPERATION_GET_NEXT_PROGRAM_ID:
        case EBPF_OPERATION_GET_PINNED_MAP_INFO:
        case EBPF_OPERATION_GET_NEXT_PINNED_PROGRAM_PATH:
        case EBPF_OPERATION_GET_NEXT_PINNED_OBJECT_PATH:
        case EBPF_OPERATION_LOAD_NATIVE_PROGRAMS:
        case EBPF_OPERATION_LOAD_NATIVE_PROGRAMS_EX:
        case EBPF_OPERATION_GET_NAMESPACE:
            scoped = true;
            break;
        case EBPF_OPERATION_UNLINK_PROGRAM:
            scoped = request_size < EBPF_OFFSET_OF(ebpf_operation_unlink_program_request_t, data) ||
                     static_cast<const ebpf_operation_unlink_program_request_t*>(request)->link_handle ==
                         ebpf_handle_invalid;
            break;
        default:
            break;
        }
    }
    if (scoped && !_thread_namespace_valid) {
        return ERROR_INVALID_STATE;
    }
    ebpf_handle_t candidate = get_sync_device_handle();
    if (candidate == ebpf_handle_invalid) {
        uint32_t error = GetLastError();
        return error != ERROR_SUCCESS ? error : ERROR_INVALID_HANDLE;
    }
    bool& bound = _namespace_operation_handle != ebpf_handle_invalid ? _namespace_operation_bound : _sync_device_bound;
    if (scoped && !bound) {
        uint32_t error = _set_file_namespace(candidate, _thread_namespace);
        if (error != ERROR_SUCCESS) {
            clean_up_sync_device_handle();
            return error;
        }
        bound = true;
        if (candidate == _sync_device_handle) {
            _sync_device_bound = true;
        }
    }
    if (_namespace_operation_depth != 0 && _namespace_operation_handle == ebpf_handle_invalid) {
        _namespace_operation_handle = candidate;
        _namespace_operation_bound = _sync_device_bound;
    }
    *handle = candidate;
    return ERROR_SUCCESS;
}

ebpf_result_t
set_thread_namespace(_In_ const GUID* namespace_id) noexcept
{
    if (namespace_id == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    if (_namespace_operation_depth != 0) {
        return EBPF_INVALID_STATE;
    }
    bool changed = !IsEqualGUID(*namespace_id, _thread_namespace);
    if (changed && _thread_namespace_generation == UINT64_MAX) {
        return EBPF_ARITHMETIC_OVERFLOW;
    }
    ebpf_handle_t handle = get_sync_device_handle();
    if (handle == ebpf_handle_invalid) {
        return win32_error_code_to_ebpf_result(GetLastError());
    }
    ebpf_result_t result = win32_error_code_to_ebpf_result(_set_file_namespace(handle, *namespace_id));
    if (result != EBPF_SUCCESS) {
        clean_up_sync_device_handle();
        return result;
    }
    _thread_namespace = *namespace_id;
    _thread_namespace_generation += changed ? 1 : 0;
    _thread_namespace_valid = true;
    _sync_device_bound = true;
    return EBPF_SUCCESS;
}

ebpf_result_t
get_thread_namespace(_Out_ GUID* namespace_id) noexcept
{
    if (namespace_id == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_operation_get_namespace_request_t request{{sizeof(request), EBPF_OPERATION_GET_NAMESPACE}};
    ebpf_operation_get_namespace_reply_t reply{};
    ebpf_result_t result = win32_error_code_to_ebpf_result(invoke_ioctl(request, reply));
    if (result != EBPF_SUCCESS) {
        clean_up_sync_device_handle();
        return result;
    }
    if (reply.header.id != EBPF_OPERATION_GET_NAMESPACE || reply.header.length != sizeof(reply) ||
        !IsEqualGUID(reply.namespace_id, _thread_namespace)) {
        _thread_namespace_valid = false;
        clean_up_sync_device_handle();
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "Invalid thread namespace binding reply");
        return EBPF_INVALID_STATE;
    }
    *namespace_id = reply.namespace_id;
    return EBPF_SUCCESS;
}

ebpf_handle_t
get_async_device_handle()
{
    if (_async_device_handle == ebpf_handle_invalid) {
        // Ignore failures.
        (void)initialize_async_device_handle();
    }
    return _async_device_handle;
}

void
clean_up_async_ioctl_completion(_Inout_opt_ _Post_invalid_ async_ioctl_completion_t* async_ioctl_completion)
{
    if (async_ioctl_completion != nullptr) {
        if (async_ioctl_completion->wait != nullptr) {
            // Unregister the wait by setting the event to NULL.
            SetThreadpoolWait(async_ioctl_completion->wait, nullptr, nullptr);

            // Close the wait.
            CloseThreadpoolWait(async_ioctl_completion->wait);
        }

        if (async_ioctl_completion->overlapped.hEvent != nullptr) {
            ::CloseHandle(async_ioctl_completion->overlapped.hEvent);
        }

        ebpf_free(async_ioctl_completion);
    }
}

_Must_inspect_result_ ebpf_result_t
register_wait_async_ioctl_operation(_Inout_ async_ioctl_completion_t* async_ioctl_completion)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t win32_error = ERROR_SUCCESS;

    EBPF_LOG_ENTRY();

    // This function registers wait for the async IOCTL operation completion, by resetting
    // the OVERLAPPED structure used for the async IOCTL, resetting the event object used in the previous call,
    // and arming the threadpool object once more with the event handle.

    // Save the overlapped event handle.
    HANDLE event = async_ioctl_completion->overlapped.hEvent;

    // Reset the overlapped object.
    memset(&async_ioctl_completion->overlapped, 0, sizeof(OVERLAPPED));

    if (event == nullptr) {
        // Create a new event object for OVERLAPPED struct.
        async_ioctl_completion->overlapped.hEvent = CreateEvent(
            nullptr,  // default security attributes
            true,     // manual reset event
            false,    // not signaled
            nullptr); // no name
        if (async_ioctl_completion->overlapped.hEvent == nullptr) {
            win32_error = GetLastError();
            result = win32_error_code_to_ebpf_result(win32_error);
            _Analysis_assume_(result != EBPF_SUCCESS);
            EBPF_BAIL_ON_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, CreateEvent, win32_error, Exit);
        }
    } else {
        // Reset the event.
        if (!ResetEvent(event)) {
            win32_error = GetLastError();
            result = win32_error_code_to_ebpf_result(win32_error);
            _Analysis_assume_(result != EBPF_SUCCESS);
            EBPF_BAIL_ON_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, ResetEvent, win32_error, Exit);
        }
        async_ioctl_completion->overlapped.hEvent = event;
    }

    // Set the event on the thread-pool wait object.
    ebpf_assert(async_ioctl_completion->wait != nullptr);
    _Analysis_assume_(async_ioctl_completion->wait != nullptr);
    SetThreadpoolWait(async_ioctl_completion->wait, async_ioctl_completion->overlapped.hEvent, nullptr);

Exit:
    EBPF_RETURN_RESULT(result);
}

_Ret_notnull_ OVERLAPPED*
get_async_ioctl_operation_overlapped(_In_ const async_ioctl_completion_t* async_ioctl_completion)
{
    return const_cast<OVERLAPPED*>(&async_ioctl_completion->overlapped);
}

_Must_inspect_result_ ebpf_result_t
get_async_ioctl_result(_In_ const async_ioctl_completion_t* ioctl_completion)
{
    ebpf_result_t result = EBPF_SUCCESS;
    unsigned long dummy;
    if (!GetOverlappedResult(
            reinterpret_cast<HANDLE>(get_async_device_handle()),
            get_async_ioctl_operation_overlapped(ioctl_completion),
            &dummy,
            FALSE)) {
        result = win32_error_code_to_ebpf_result(GetLastError());
    }

    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
initialize_async_ioctl_operation(
    _Inout_opt_ void* callback_context,
    _In_ const async_ioctl_completion_callback_t callback,
    _Outptr_ async_ioctl_completion_t** async_ioctl_completion)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t win32_error = ERROR_SUCCESS;
    *async_ioctl_completion = nullptr;

    async_ioctl_completion_context_t* local_async_ioctl_completion =
        (async_ioctl_completion_context_t*)ebpf_allocate_with_tag(
            sizeof(async_ioctl_completion_context_t), EBPF_POOL_TAG_DEFAULT);
    if (local_async_ioctl_completion == nullptr) {
        result = EBPF_NO_MEMORY;
        EBPF_BAIL_ON_ALLOC_FAILURE(local_async_ioctl_completion, Exit);
    }

    local_async_ioctl_completion->callback_context = callback_context;
    local_async_ioctl_completion->callback = callback;

    // Set up threadpool wait for the overlapped hEvent and pass the async completion context as wait callback context.
    local_async_ioctl_completion->wait = CreateThreadpoolWait(
        [](_Inout_ TP_CALLBACK_INSTANCE* instance,
           _Inout_ void* context,
           _Inout_ PTP_WAIT wait,
           TP_WAIT_RESULT wait_result) {
            UNREFERENCED_PARAMETER(instance);
            UNREFERENCED_PARAMETER(wait);
            UNREFERENCED_PARAMETER(wait_result);

            async_ioctl_completion_context_t* local_async_ioctl_completion = (async_ioctl_completion_context_t*)context;
            local_async_ioctl_completion->callback(local_async_ioctl_completion->callback_context);
        },
        local_async_ioctl_completion,
        nullptr);
    if (local_async_ioctl_completion->wait == nullptr) {
        win32_error = GetLastError();
        result = win32_error_code_to_ebpf_result(win32_error);
        _Analysis_assume_(result != EBPF_SUCCESS);
        EBPF_BAIL_ON_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, CreateThreadpoolWait, win32_error, Exit);
    }

    // Register for wait on the completion of the async IOCTL.
    result = register_wait_async_ioctl_operation(local_async_ioctl_completion);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    *async_ioctl_completion = local_async_ioctl_completion;

Exit:
    if (result != EBPF_SUCCESS) {
        clean_up_async_ioctl_completion(local_async_ioctl_completion);
    }

    EBPF_RETURN_RESULT(result);
}

bool
cancel_async_ioctl(_Inout_opt_ OVERLAPPED* overlapped = nullptr)
{
    return Platform::CancelIoEx(get_async_device_handle(), overlapped);
}
