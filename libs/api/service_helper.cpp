// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "pch.h"

#include <fcntl.h>
#include <io.h>
#include <mutex>

#include "api_internal.h"
#include "bpf.h"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "ebpf_protocol.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_serialize.h"

using namespace std;

#define MAX_RETRY_COUNT 20
#define WAIT_TIME 500 // in ms.

wstring
guid_to_wide_string(GUID* guid)
{
    wchar_t guid_string[37] = {0};
    swprintf(
        guid_string,
        sizeof(guid_string) / sizeof(guid_string[0]),
        L"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        guid->Data1,
        guid->Data2,
        guid->Data3,
        guid->Data4[0],
        guid->Data4[1],
        guid->Data4[2],
        guid->Data4[3],
        guid->Data4[4],
        guid->Data4[5],
        guid->Data4[6],
        guid->Data4[7]);

    return wstring(guid_string);
}

/*
ebpf_result_t
create_service(
    _In_ const wchar_t* service_name, _In_ const wchar_t* file_path, bool kernel_mode, _Out_ SC_HANDLE* service_handle)
{
    SC_HANDLE local_service_handle = nullptr;
    SC_HANDLE scm_handle = nullptr;
    int error;
    ebpf_result_t result = EBPF_SUCCESS;
    *service_handle = nullptr;
    DWORD service_type = kernel_mode ? SERVICE_KERNEL_DRIVER : SERVICE_WIN32_OWN_PROCESS;

    scm_handle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm_handle == nullptr) {
        return win32_error_code_to_ebpf_result(GetLastError());
    }

    WCHAR full_file_path[MAX_PATH] = {0};
    error = GetFullPathName(file_path, MAX_PATH, full_file_path, nullptr);
    if (error == 0) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        goto Done;
    }

    // Install the driver service.
    local_service_handle = CreateService(
        scm_handle,           // SCM database
        service_name,         // name of service
        service_name,         // service name to display
        SERVICE_ALL_ACCESS,   // desired access
        service_type,         // service type
        SERVICE_DEMAND_START, // start type
        SERVICE_ERROR_NORMAL, // error control type
        full_file_path,       // path to service's binary
        nullptr,              // no load ordering group
        nullptr,              // no tag identifier
        nullptr,              // no dependencies
        nullptr,              // No service start name
        nullptr);             // no password

    if (local_service_handle == nullptr) {
        error = GetLastError();
        return win32_error_code_to_ebpf_result(error);
    }
    *service_handle = local_service_handle;

Done:
    if (scm_handle != nullptr) {
        CloseServiceHandle(scm_handle);
    }
    return result;
}

ebpf_result_t
delete_service(SC_HANDLE service_handle)
{
    if (!service_handle) {
        return EBPF_SUCCESS;
    }

    int error;
    ebpf_result_t result = EBPF_SUCCESS;
    if (!DeleteService(service_handle)) {
        error = GetLastError();
        result = win32_error_code_to_ebpf_result(error);
    }

    CloseServiceHandle(service_handle);

    return result;
}

static bool
_check_service_state(SC_HANDLE service_handle, DWORD expected_state, DWORD* final_state)
{
    int retry_count = 0;
    bool status = false;
    int error;
    SERVICE_STATUS service_status = {0};

    // Query service state.
    while (retry_count < MAX_RETRY_COUNT) {
        if (!QueryServiceStatus(service_handle, &service_status)) {
            error = GetLastError();
            break;
        } else if (service_status.dwCurrentState == expected_state) {
            status = true;
            break;
        } else {
            Sleep(WAIT_TIME);
            retry_count++;
        }
    }

    *final_state = service_status.dwCurrentState;
    return status;
}

ebpf_result_t
stop_service(SC_HANDLE service_handle)
{
    SERVICE_STATUS status;
    bool service_stopped = false;
    DWORD service_state;
    int error = ERROR_SUCCESS;

    if (service_handle == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (!ControlService(service_handle, SERVICE_CONTROL_STOP, &status)) {
        error = GetLastError();
        return win32_error_code_to_ebpf_result(error);
    }

    service_stopped = _check_service_state(service_handle, SERVICE_STOPPED, &service_state);
    if (!service_stopped) {
        error = ERROR_SERVICE_REQUEST_TIMEOUT;
    }

    return win32_error_code_to_ebpf_result(error);
}
*/