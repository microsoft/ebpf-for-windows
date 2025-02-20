// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_api.h"

#include <crtdbg.h> // For _CrtSetReportMode
#include <cstdlib>
#include <io.h>
#include <stdint.h>
#include <string>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <Windows.h>

class _invalid_parameter_suppression
{
  public:
    _invalid_parameter_suppression()
    {
        _CrtSetReportMode(_CRT_ASSERT, 0);
        previous_handler = _set_invalid_parameter_handler(_ignore_invalid_parameter);
    }
    ~_invalid_parameter_suppression() { _set_invalid_parameter_handler(previous_handler); }

  private:
    static void
    _ignore_invalid_parameter(
        const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved)
    {
        UNREFERENCED_PARAMETER(expression);
        UNREFERENCED_PARAMETER(function);
        UNREFERENCED_PARAMETER(file);
        UNREFERENCED_PARAMETER(line);
        UNREFERENCED_PARAMETER(pReserved);
    }
    _invalid_parameter_handler previous_handler;
};

namespace Platform {
bool
DeviceIoControl(
    _In_ ebpf_handle_t device_handle,
    uint32_t io_control_code,
    _In_reads_bytes_opt_(input_buffer_size) void* input_buffer,
    uint32_t input_buffer_size,
    _Out_writes_bytes_to_opt_(output_buffer_size, *count_of_bytes_returned) void* output_buffer,
    uint32_t output_buffer_size,
    _Out_opt_ uint32_t* count_of_bytes_returned,
    _Inout_opt_ OVERLAPPED* overlapped)
{
    return ::DeviceIoControl(
        reinterpret_cast<HANDLE>(device_handle),
        io_control_code,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        (unsigned long*)count_of_bytes_returned,
        overlapped);
}

bool
CancelIoEx(_In_ ebpf_handle_t device_handle, _In_opt_ OVERLAPPED* overlapped)
{
    return ::CancelIoEx(reinterpret_cast<HANDLE>(device_handle), overlapped);
}

ebpf_handle_t
CreateFileW(
    _In_z_ PCWSTR file_name,
    uint32_t desired_access,
    uint32_t share_mode,
    _In_opt_ SECURITY_ATTRIBUTES* security_attributes,
    uint32_t creation_disposition,
    uint32_t flags_and_attributes,
    _In_opt_ ebpf_handle_t template_file)
{
    return reinterpret_cast<ebpf_handle_t>(::CreateFileW(
        file_name,
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_and_attributes,
        reinterpret_cast<HANDLE>(template_file)));
}

bool
CloseHandle(_In_ _Post_ptr_invalid_ ebpf_handle_t handle)
{
    return ::CloseHandle(reinterpret_cast<HANDLE>(handle));
}

bool
DuplicateHandle(
    _In_ ebpf_handle_t source_process_handle,
    _In_ ebpf_handle_t source_handle,
    _In_ ebpf_handle_t target_process_handle,
    _Out_ ebpf_handle_t* target_handle,
    uint32_t desired_access,
    bool inherit_handle,
    uint32_t options)
{
    return ::DuplicateHandle(
        reinterpret_cast<HANDLE>(source_process_handle),
        reinterpret_cast<HANDLE>(source_handle),
        reinterpret_cast<HANDLE>(target_process_handle),
        reinterpret_cast<LPHANDLE>(target_handle),
        desired_access,
        inherit_handle,
        options);
}

int
_open_osfhandle(intptr_t os_file_handle, int flags)
{
    _invalid_parameter_suppression suppress;
    return ::_open_osfhandle(os_file_handle, flags);
}

intptr_t
_get_osfhandle(int file_descriptor)
{
    _invalid_parameter_suppression suppress;
    return ::_get_osfhandle(file_descriptor);
}

int
_close(int file_descriptor)
{
    _invalid_parameter_suppression suppress;
    return ::_close(file_descriptor);
}

int
_dup(int file_descriptor)
{
    _invalid_parameter_suppression suppress;
    return ::_dup(file_descriptor);
}

bool
_is_native_program(_In_z_ const char* file_name)
{
    std::string file_name_string(file_name);
    std::string file_extension = file_name_string.substr(file_name_string.find_last_of(".") + 1);
    if (file_extension == "sys") {
        return true;
    }

    return false;
}

uint32_t
_create_registry_key(HKEY root_key, _In_z_ const wchar_t* path)
{
    HKEY key = nullptr;
    uint32_t error;
    error = RegCreateKeyEx(root_key, path, 0, NULL, 0, KEY_WRITE | DELETE | KEY_READ, NULL, &key, NULL);

    if (key != nullptr) {
        RegCloseKey(key);
    }

    return error;
}

uint32_t
_update_registry_value(
    HKEY root_key,
    _In_z_ const wchar_t* sub_key,
    unsigned long type,
    _In_z_ const wchar_t* value_name,
    _In_reads_bytes_(value_size) const void* value,
    uint32_t value_size)
{
    HKEY key = nullptr;
    uint32_t error = RegOpenKeyEx(root_key, sub_key, 0, KEY_WRITE | DELETE | KEY_READ, &key);
    if (error != ERROR_SUCCESS) {
        return error;
    }
    error = RegSetValueEx(key, value_name, 0, type, (PBYTE)value, value_size);
    RegCloseKey(key);

    return error;
}

static bool
_check_service_state(SC_HANDLE service_handle, unsigned long expected_state, _Out_ unsigned long* final_state)
{
#define MAX_RETRY_COUNT 20
#define WAIT_TIME_IN_MS 500

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
            Sleep(WAIT_TIME_IN_MS);
            retry_count++;
        }
    }

    *final_state = service_status.dwCurrentState;
    return status;
}

uint32_t
_create_service(_In_z_ const wchar_t* service_name, _In_z_ const wchar_t* file_path, _Out_ SC_HANDLE* service_handle)
{
    SC_HANDLE local_service_handle = nullptr;
    SC_HANDLE scm_handle = nullptr;
    int error = ERROR_SUCCESS;
    int count;
    *service_handle = nullptr;
    unsigned long service_type = SERVICE_KERNEL_DRIVER;

    scm_handle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm_handle == nullptr) {
        return GetLastError();
    }

    wchar_t full_file_path[MAX_PATH] = {0};
    count = GetFullPathName(file_path, MAX_PATH, full_file_path, nullptr);
    if (count == 0) {
        error = GetLastError();
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
        goto Done;
    }
    *service_handle = local_service_handle;

Done:
    if (scm_handle != nullptr) {
        CloseServiceHandle(scm_handle);
    }
    return error;
}

bool
_query_service_status(SC_HANDLE service_handle, _Inout_ SERVICE_STATUS* status)
{
    return QueryServiceStatus(service_handle, status);
}

uint32_t
_delete_service(SC_HANDLE service_handle)
{
    if (!service_handle) {
        return EBPF_SUCCESS;
    }

    int error = ERROR_SUCCESS;
    if (!DeleteService(service_handle)) {
        error = GetLastError();
    }

    CloseServiceHandle(service_handle);
    return error;
}

uint32_t
_stop_service(SC_HANDLE service_handle)
{
    SERVICE_STATUS status;
    bool service_stopped = false;
    unsigned long service_state;
    int error = ERROR_SUCCESS;

    if (service_handle == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (!ControlService(service_handle, SERVICE_CONTROL_STOP, &status)) {
        return GetLastError();
    }

    service_stopped = _check_service_state(service_handle, SERVICE_STOPPED, &service_state);
    if (!service_stopped) {
        error = ERROR_SERVICE_REQUEST_TIMEOUT;
    }

    return error;
}

} // namespace Platform
