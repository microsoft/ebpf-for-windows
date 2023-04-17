// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_api.h"
#include "platform.h"

// Device type
#define EBPF_IOCTL_TYPE FILE_DEVICE_NETWORK

// Function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_EBPF_CTL_METHOD_BUFFERED CTL_CODE(EBPF_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Maximum attempts to invoke an IOCTL.
#define IOCTL_MAX_ATTEMPTS 16

typedef std::vector<uint8_t> ebpf_protocol_buffer_t;
typedef std::vector<uint8_t> ebpf_code_buffer_t;

typedef struct empty_reply
{
} empty_reply_t;

static empty_reply_t _empty_reply;

_Must_inspect_result_ ebpf_result_t
initialize_device_handle();

void
clean_up_device_handle();

ebpf_handle_t
get_device_handle();

typedef ebpf_result_t (*async_ioctl_completion_callback_t)(_Inout_opt_ void* completion_context);

typedef struct _async_ioctl_completion_context async_ioctl_completion_t;

_Must_inspect_result_ ebpf_result_t
initialize_async_ioctl_operation(
    _Inout_opt_ void* callback_context,
    _In_ const async_ioctl_completion_callback_t callback,
    _Outptr_ async_ioctl_completion_t** async_ioctl_completion);

_Must_inspect_result_ ebpf_result_t
register_wait_async_ioctl_operation(_Inout_ async_ioctl_completion_t* async_ioctl_completion);

void
clean_up_async_ioctl_completion(_Inout_opt_ _Post_invalid_ async_ioctl_completion_t* async_ioctl_completion);

_Ret_notnull_ OVERLAPPED*
get_async_ioctl_operation_overlapped(_In_ const async_ioctl_completion_t* ioctl_completion);

bool
cancel_async_ioctl(_Inout_opt_ OVERLAPPED* overlapped);

_Must_inspect_result_ ebpf_result_t
get_async_ioctl_result(_In_ const async_ioctl_completion_t* ioctl_completion);

template <typename request_t, typename reply_t = empty_reply_t>
uint32_t
invoke_ioctl(request_t& request, reply_t& reply = _empty_reply, _Inout_opt_ OVERLAPPED* overlapped = nullptr)
{
    uint32_t return_value = ERROR_SUCCESS;
    uint32_t actual_reply_size;
    uint32_t request_size;
    void* request_ptr;
    uint32_t reply_size;
    void* reply_ptr;
    bool variable_reply_size = false;

    if constexpr (std::is_same<request_t, nullptr_t>::value) {
        request_size = 0;
        request_ptr = nullptr;
    } else if constexpr (std::is_same<request_t, ebpf_protocol_buffer_t>::value) {
        request_size = static_cast<uint32_t>(request.size());
        request_ptr = request.data();
    } else {
        request_size = sizeof(request);
        request_ptr = &request;
    }

    if constexpr (std::is_same<reply_t, nullptr_t>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    } else if constexpr (std::is_same<reply_t, ebpf_protocol_buffer_t>::value) {
        reply_size = static_cast<uint32_t>(reply.size());
        reply_ptr = reply.data();
        variable_reply_size = true;
    } else if constexpr (std::is_same<reply_t, empty_reply>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    } else {
        reply_size = static_cast<uint32_t>(sizeof(reply));
        reply_ptr = &reply;
    }

    auto success = Platform::DeviceIoControl(
        get_device_handle(),
        IOCTL_EBPF_CTL_METHOD_BUFFERED,
        request_ptr,
        request_size,
        reply_ptr,
        reply_size,
        &actual_reply_size,
        overlapped);

    if (!success) {
        return_value = GetLastError();
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, DeviceIoControl);
        goto Exit;
    }

    if (actual_reply_size != reply_size && !variable_reply_size) {
        return_value = ERROR_INVALID_PARAMETER;
        goto Exit;
    }

Exit:
    EBPF_RETURN_ERROR(return_value);
}