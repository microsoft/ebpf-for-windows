// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "header.h"
#include "service_helper.h"

#define MAX_RETRY_COUNT 20
#define WAIT_TIME 500 // in ms.

int
service_install_helper::initialize()
{
    int error;
    int retry_count = 0;
    SERVICE_SID_INFO sid_info = {0};

    if (initialized) {
        return ERROR_SUCCESS;
    }

    scm_handle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm_handle == nullptr) {
        error = GetLastError();
        return error;
    }

QueryService:
    service_handle = OpenService(scm_handle, service_name.c_str(), SERVICE_ALL_ACCESS);
    if (service_handle == nullptr) {
        wchar_t file_path[MAX_PATH] = {0};
        error = GetFullPathName(binary_name.c_str(), MAX_PATH, file_path, nullptr);
        if (error == 0) {
            error = GetLastError();
            printf("GetFullPathName failed, 0x%x.\n", error);
            return error;
        }

        // Install the service as LocalService.
        service_handle = CreateService(
            scm_handle,                    // SCM database
            service_name.c_str(),          // name of service
            service_name.c_str(),          // service name to display
            SERVICE_ALL_ACCESS,            // desired access
            service_type,                  // service type
            SERVICE_AUTO_START,            // start type
            SERVICE_ERROR_NORMAL,          // error control type
            file_path,                     // path to service's binary
            nullptr,                       // no load ordering group
            nullptr,                       // no tag identifier
            nullptr,                       // no dependencies
            L"NT AUTHORITY\\LocalService", // LocalService account
            nullptr);                      // no password

        if (service_handle == nullptr) {
            error = GetLastError();
            if (error == ERROR_SERVICE_EXISTS && retry_count < MAX_RETRY_COUNT) {
                retry_count++;
                goto QueryService;
            }
            printf("CreateService for %ws failed, 0x%x.\n", service_name.c_str(), error);
            return error;
        }

        // Set service SID type to restricted.
        sid_info.dwServiceSidType = SERVICE_SID_TYPE_RESTRICTED;
        if (!ChangeServiceConfig2(service_handle, SERVICE_CONFIG_SERVICE_SID_INFO, &sid_info)) {
            error = GetLastError();
            printf("ChangeServiceConfig2 for %ws failed, 0x%x.\n", service_name.c_str(), error);
            return error;
        }
    } else {
        already_installed = true;
    }

    error = start_service();
    if (error == ERROR_SUCCESS) {
        initialized = true;
    }

    return error;
}

void
service_install_helper::cleanup()
{
    if (service_handle != nullptr && !already_installed) {
        stop_service();
        DeleteService(service_handle);

        CloseServiceHandle(service_handle);
        service_handle = nullptr;
    }
    if (scm_handle != nullptr) {
        CloseServiceHandle(scm_handle);
        scm_handle = nullptr;
    }

    initialized = false;
}

int
service_install_helper::start_service()
{
    int error = ERROR_SUCCESS;
    bool service_running = false;
    unsigned long service_state;

    if ((service_handle != nullptr) && !StartService(service_handle, 0, nullptr)) {
        error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("StartService for %ws failed, 0x%x.\n", service_name.c_str(), error);
            return error;
        }
        error = ERROR_SUCCESS;
    }

    service_running = check_service_state(SERVICE_RUNNING, &service_state);
    if (!service_running) {
        error = ERROR_SERVICE_REQUEST_TIMEOUT;
        printf(
            "start_service: Service %ws failed to move to running state. Current state = %d\n",
            service_name.c_str(),
            service_state);
    }

    return error;
}

int
service_install_helper::stop_service()
{
    SERVICE_STATUS status;
    bool service_stopped = false;
    unsigned long service_state;
    int error = ERROR_SUCCESS;

    if ((service_handle != nullptr) && !ControlService(service_handle, SERVICE_CONTROL_STOP, &status)) {
        error = GetLastError();
        return error;
    }

    service_stopped = check_service_state(SERVICE_STOPPED, &service_state);
    if (!service_stopped) {
        error = ERROR_SERVICE_REQUEST_TIMEOUT;
    }
    return error;
}

bool
service_install_helper::check_service_state(unsigned long expected_state, unsigned long* final_state)
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
