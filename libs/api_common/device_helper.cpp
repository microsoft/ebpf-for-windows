// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Contains code to manage device for kernel mode execution context.
 */

#include "api_common.hpp"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
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

static ebpf_handle_t _device_handle = ebpf_handle_invalid;
static std::mutex _mutex;

_Must_inspect_result_ ebpf_result_t
initialize_device_handle()
{
    std::scoped_lock lock(_mutex);

    if (_device_handle != ebpf_handle_invalid) {
        return EBPF_ALREADY_INITIALIZED;
    }

    _device_handle = Platform::CreateFile(
        EBPF_DEVICE_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, 0);

    if (_device_handle == ebpf_handle_invalid) {
        return win32_error_code_to_ebpf_result(GetLastError());
    }

    return EBPF_SUCCESS;
}

void
clean_up_device_handle()
{
    std::scoped_lock lock(_mutex);

    if (_device_handle != ebpf_handle_invalid) {
        Platform::CloseHandle(_device_handle);
        _device_handle = ebpf_handle_invalid;
    }
}

ebpf_handle_t
get_device_handle()
{
    if (_device_handle == ebpf_handle_invalid) {
        // Ignore failures.
        (void)initialize_device_handle();
    }

    return _device_handle;
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
            result = win32_error_code_to_ebpf_result(GetLastError());
            _Analysis_assume_(result != EBPF_SUCCESS);
            EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, CreateEvent);
            goto Exit;
        }
    } else {
        // Reset the event.
        if (!ResetEvent(event)) {
            result = win32_error_code_to_ebpf_result(GetLastError());
            _Analysis_assume_(result != EBPF_SUCCESS);
            EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, CreateEvent);
            goto Exit;
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
    unsigned long dummy;
    if (!GetOverlappedResult(
            reinterpret_cast<HANDLE>(get_device_handle()),
            get_async_ioctl_operation_overlapped(ioctl_completion),
            &dummy,
            FALSE))
        return win32_error_code_to_ebpf_result(GetLastError());
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
initialize_async_ioctl_operation(
    _Inout_opt_ void* callback_context,
    _In_ const async_ioctl_completion_callback_t callback,
    _Outptr_ async_ioctl_completion_t** async_ioctl_completion)
{
    ebpf_result_t result = EBPF_SUCCESS;
    *async_ioctl_completion = nullptr;

    async_ioctl_completion_context_t* local_async_ioctl_completion =
        (async_ioctl_completion_context_t*)ebpf_allocate(sizeof(async_ioctl_completion_context_t));
    if (local_async_ioctl_completion == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
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
        result = win32_error_code_to_ebpf_result(GetLastError());
        _Analysis_assume_(result != EBPF_SUCCESS);
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, CreateThreadpoolWait);
        goto Exit;
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
    return Platform::CancelIoEx(get_device_handle(), overlapped);
}
