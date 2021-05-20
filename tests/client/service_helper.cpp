// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "header.h"
#include "service_helper.h"

#define MAX_RETRY_COUNT 10
#define WAIT_TIME 500 // in ms.

int
service_install_helper::initialize()
{
    int error;
    scm_handle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm_handle == nullptr) {
        error = GetLastError();
        return error;
    }

QueryService:
    service_handle = OpenService(scm_handle, service_name.c_str(), SERVICE_ALL_ACCESS);
    if (service_handle == nullptr) {
        printf("initialize: OpenService for %ws failed, 0x%x.\n", service_name.c_str(), GetLastError());
        WCHAR file_path[MAX_PATH] = {0};
        error = GetFullPathName(binary_name.c_str(), MAX_PATH, file_path, nullptr);
        if (error == 0) {
            error = GetLastError();
            printf("GetFullPathName failed, 0x%x.\n", error);
            return error;
        }

        // Install the service
        service_handle = CreateService(
            scm_handle,                // SCM database
            service_name.c_str(),      // name of service
            service_name.c_str(),      // service name to display
            SERVICE_ALL_ACCESS,        // desired access
            SERVICE_WIN32_OWN_PROCESS, // service type
            SERVICE_AUTO_START,        // start type
            SERVICE_ERROR_NORMAL,      // error control type
            file_path,                 // path to service's binary
            nullptr,                   // no load ordering group
            nullptr,                   // no tag identifier
            nullptr,                   // no dependencies
            nullptr,                   // LocalSystem account
            nullptr);                  // no password

        if (service_handle == nullptr) {
            error = GetLastError();
            if (error == ERROR_SERVICE_EXISTS) {
                goto QueryService;
            }
            printf("CreateService failed, 0x%x.\n", error);
            return error;
        }
    } else {
        already_installed = true;
        printf("Service %ws already installed.\n", service_name.c_str());
    }

    return start_service();
}

void
service_install_helper::uninitialize()
{
    if (service_handle != nullptr && !already_installed) {
        stop_service();
        if (!DeleteService(service_handle)) {
            DWORD error = GetLastError();
            printf("DeleteService for %ws failed, 0x%x.\n", service_name.c_str(), error);
        }
        CloseServiceHandle(service_handle);
        service_handle = nullptr;
    }
    if (scm_handle != nullptr) {
        CloseServiceHandle(scm_handle);
        scm_handle = nullptr;
    }
}

int
service_install_helper::start_service()
{
    int error = ERROR_SUCCESS;
    bool service_running = false;
    DWORD service_state;

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
    } else {
        printf("start_service: Service %ws successfully started.\n", service_name.c_str());
    }

    return error;
}

int
service_install_helper::stop_service()
{
    SERVICE_STATUS status;
    bool service_stopped = false;
    DWORD service_state;
    int error = ERROR_SUCCESS;

    if ((service_handle != nullptr) && !ControlService(service_handle, SERVICE_CONTROL_STOP, &status)) {
        error = GetLastError();
        printf("StopService for %ws failed, 0x%x.\n", service_name.c_str(), error);
        return error;
    }

    service_stopped = check_service_state(SERVICE_STOPPED, &service_state);
    if (!service_stopped) {
        error = ERROR_SERVICE_REQUEST_TIMEOUT;
        printf(
            "stop_service: Service %ws failed to move to stopped state. Current state = %d\n",
            service_name.c_str(),
            service_state);
    } else {
        printf("stop_service: Service %ws successfully stopped.\n", service_name.c_str());
    }
    return error;
}

bool
service_install_helper::check_service_state(DWORD expected_state, DWORD* final_state)
{
    int retry_count = 0;
    bool status = false;
    int error;
    SERVICE_STATUS service_status = {0};

    // Query service state.
    while (retry_count < MAX_RETRY_COUNT) {
        if (!QueryServiceStatus(service_handle, &service_status)) {
            error = GetLastError();
            printf("start_service: failed to query service %ws status 0x%x\n", service_name.c_str(), error);
            break;
        } else if (service_status.dwCurrentState == expected_state) {
            status = true;
            break;
        } else {
            printf(
                "start_service: service %ws not yet in desired state, state=%d, desired_state=%d\n",
                service_name.c_str(),
                service_status.dwCurrentState,
                expected_state);
            Sleep(WAIT_TIME);
            retry_count++;
        }
    }

    *final_state = service_status.dwCurrentState;
    return status;
}
