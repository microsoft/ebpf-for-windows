/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/

#include "pch.h"
#define EBPF_API
extern "C"
{
#include "api.h"
#include "ubpf.h"
}

#include "protocol.h"
#include "UnwindHelper.h"

#include "Verifier.h"

#define MAX_CODE_SIZE (32 * 1024) // 32 KB

// Device type 
#define EBPF_IOCTL_TYPE FILE_DEVICE_NETWORK

// Function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_EBPFCTL_METHOD_BUFFERED \
    CTL_CODE( EBPF_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS  )

static HANDLE device_handle = INVALID_HANDLE_VALUE;

template <typename request_t, typename reply_t>
static DWORD invoke_ioctl(HANDLE handle, request_t request, reply_t reply)
{
    DWORD actual_reply_size;
    DWORD request_size;
    void* request_ptr;
    DWORD reply_size;
    void* reply_ptr;

    if constexpr (std::is_same<request_t, nullptr_t>::value) {
        request_size = 0;
        request_ptr = nullptr;
    }
    else if constexpr (std::is_same< request_t, std::vector<uint8_t>>::value)
    {
        request_size = static_cast<DWORD>(request.size());
        request_ptr = request.data();
    }
    else
    {
        request_size = sizeof(*request);
        request_ptr = request;
    }

    if constexpr (std::is_same<reply_t, nullptr_t>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    }
    else if constexpr (std::is_same< reply_t, std::vector<uint8_t>>::value)
    {
        reply_size = reply.size();
        reply_ptr = reply.data();
    }
    else
    {
        reply_size = sizeof(*reply);
        reply_ptr = reply;
    }

    auto result = DeviceIoControl(
        handle,
        (DWORD)IOCTL_EBPFCTL_METHOD_BUFFERED,
        request_ptr,
        request_size,
        reply_ptr,
        reply_size,
        &actual_reply_size,
        nullptr);

    if (actual_reply_size != reply_size)
    {
        return ERROR_INVALID_PARAMETER;
    }

    return result;
}

DWORD EbpfApiInit()
{
    LPCWSTR ebpfDeviceName = L"\\\\.\\EbpfIoDevice";

    if (device_handle != INVALID_HANDLE_VALUE)
    {
        return ERROR_ALREADY_INITIALIZED;
    }

    device_handle = CreateFile(ebpfDeviceName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (device_handle == INVALID_HANDLE_VALUE)
    {
        return GetLastError();
    }

    return 0;
}

void EbpfApiTerminate()
{
    if (device_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(device_handle);
        device_handle = INVALID_HANDLE_VALUE;
    }
}

uint64_t map_resolver(void* context, uint64_t fd)
{
    EbpfOpResolveMapRequest request{
        sizeof(request),
        EbpfOperation::resolve_map,
        fd };

    EbpfOpResolveMapReply reply;

    invoke_ioctl(context, &request, &reply);

    if (reply.header.id != EbpfOperation::resolve_map)
    {
        return 0;
    }

    return reply.address[0];
}

uint64_t helper_resolver(void* context, uint32_t helper)
{
    EbpfOpResolveHelperRequest request{
        sizeof(request),
        EbpfOperation::resolve_helper,
        helper };

    EbpfOpResolveMapReply reply;

    invoke_ioctl(context, &request, &reply);

    if (reply.header.id != EbpfOperation::resolve_helper)
    {
        return 0;
    }

    return reply.address[0];
}

DLL DWORD EbpfLoadProgram(const char* file_name, const char* section_name, HANDLE* handle, char** error_message)
{
    std::vector<uint8_t> byte_code(MAX_CODE_SIZE);
    size_t byte_code_size = byte_code.size();
    std::vector<uint8_t> machine_code(MAX_CODE_SIZE);
    size_t machine_code_size = machine_code.size();
    std::vector<uint8_t> request_buffer;
    EbpfOpLoadReply reply;
    struct ubpf_vm* vm = nullptr;
    UnwindHelper unwind([&]
        {
            if (vm)
            {
                ubpf_destroy(vm);
            }
        });

    DWORD result;

    // Verify code.
    if (verify(file_name, section_name, byte_code.data(), &byte_code_size, error_message) != 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    // JIT code.
    vm = ubpf_create();
    if (vm == nullptr)
    {
        return ERROR_OUTOFMEMORY;
    }

    if (ubpf_load(vm, byte_code.data(), static_cast<uint32_t>(byte_code.size()), error_message) < 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (ubpf_register_map_resolver(vm, device_handle, map_resolver) < 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (ubpf_register_helper_resolver(vm, device_handle, helper_resolver) < 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (ubpf_translate(vm, machine_code.data(), &machine_code_size, error_message))
    {
        return ERROR_INVALID_PARAMETER;
    }
    machine_code.resize(machine_code_size);

    request_buffer.resize(machine_code.size() + sizeof(EbpfOpHeader));
    auto header = reinterpret_cast<EbpfOpHeader*>(request_buffer.data());
    header->id = EbpfOperation::load_code;
    header->length = static_cast<uint16_t>(request_buffer.size());
    std::copy(machine_code.begin(), machine_code.end(), request_buffer.begin() + sizeof(EbpfOpHeader));

    result = invoke_ioctl(device_handle, request_buffer, &reply);

    if (result != ERROR_SUCCESS)
    {
        return result;
    }

    if (reply.header.id != EbpfOperation::load_code)
    {
        return ERROR_INVALID_PARAMETER;
    }

    *handle = reinterpret_cast<HANDLE>(reply.handle);

    return result;
}

DLL void EbpfFreeErrorMessage(char* error_message)
{
    return free(error_message);
}

DLL void EbpfUnloadProgram(HANDLE handle)
{
    // TBD:
    // CloseHandle(handle);
    return;
}

DLL DWORD EbpfAttachProgram(HANDLE handle, DWORD hook_point)
{
    EbpfOpAttachDetachRequest request{
        sizeof(request),
        EbpfOperation::attach,
        reinterpret_cast<uint64_t>(handle),
        hook_point };

    return invoke_ioctl(device_handle, &request, nullptr);
}

DLL DWORD EbpfDetachProgram(HANDLE handle, DWORD hook_point)
{
    EbpfOpAttachDetachRequest request{
        sizeof(request),
        EbpfOperation::detach,
        reinterpret_cast<uint64_t>(handle),
        hook_point };

    return invoke_ioctl(device_handle, &request, nullptr);
}


