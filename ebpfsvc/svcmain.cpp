// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_service.h"
#include "rpc_util.h"
#include "svc_common.h"

#define SERVICE_NAME TEXT("eBPFSvc")

SERVICE_STATUS ebpf_service_status;
SERVICE_STATUS_HANDLE ebpf_service_status_handle;
HANDLE ebpf_service_stop_event_handle = nullptr;

void WINAPI
service_control_handler(unsigned long ctrl);
void
service_report_event(_In_z_ wchar_t* function);
void
report_service_status(unsigned long current_state, unsigned long win32exitcode, unsigned long wait_hint);
void
service_init(unsigned long argc, _In_reads_(argc) wchar_t** argv);

void WINAPI
service_main(unsigned long argc, _In_reads_(argc) wchar_t** argv);
int
service_install();

int __cdecl wmain(unsigned long argc, _In_reads_(argc) wchar_t** argv)
{
    SERVICE_TABLE_ENTRY dispatch_table[] = {
        {(wchar_t*)SERVICE_NAME, (SERVICE_MAIN_FUNCTION*)service_main}, {nullptr, nullptr}};

    // If command-line parameter is "install", install the service.
    // Otherwise, the service is probably being started by the SCM.

    if (argc > 1) {
        if (_wcsicmp(argv[1], L"install") == 0) {
            return service_install();
        }
    }

    // This call returns when the service has stopped.
    // The process should simply terminate when the call returns.

    if (!StartServiceCtrlDispatcher(dispatch_table)) {
        service_report_event((wchar_t*)L"StartServiceCtrlDispatcher");
    }

    return 0;
}

/**
 * @brief Installs a service in the SCM database.
 *
 */
int
service_install()
{
    SC_HANDLE service_control_manager = nullptr;
    SC_HANDLE service = nullptr;
    TCHAR path[MAX_PATH];
    SERVICE_SID_INFO sid_info = {0};
    int result = ERROR_SUCCESS;

    if (!GetModuleFileName(nullptr, path, MAX_PATH)) {
        result = GetLastError();
        goto Exit;
    }

    // Get a handle to the SCM database.

    service_control_manager = OpenSCManager(
        nullptr,                // local computer
        nullptr,                // ServicesActive database
        SC_MANAGER_ALL_ACCESS); // full access rights

    if (nullptr == service_control_manager) {
        result = GetLastError();
        goto Exit;
    }

    // Create the service as LocalService.

    service = CreateService(
        service_control_manager,       // SCM database
        SERVICE_NAME,                  // name of service
        SERVICE_NAME,                  // service name to display
        SERVICE_ALL_ACCESS,            // desired access
        SERVICE_WIN32_OWN_PROCESS,     // service type
        SERVICE_DEMAND_START,          // start type
        SERVICE_ERROR_NORMAL,          // error control type
        path,                          // path to service's binary
        nullptr,                       // no load ordering group
        nullptr,                       // no tag identifier
        L"EbpfCore\0",                 // null-separated dependencies
        L"NT AUTHORITY\\LocalService", // LocalService account
        nullptr);                      // no password

    if (service == nullptr) {
        result = GetLastError();
        goto Exit;
    }

    // Set service SID type to restricted.
    sid_info.dwServiceSidType = SERVICE_SID_TYPE_RESTRICTED;
    if (!ChangeServiceConfig2(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sid_info)) {
        result = GetLastError();
        goto Exit;
    }

Exit:
    if (service != nullptr) {
        CloseServiceHandle(service);
    }
    if (service_control_manager != nullptr) {
        CloseServiceHandle(service_control_manager);
    }

    return result;
}

/**
 * @brief Entry point for the service.
 *
 * @param[in] argc Number of arguments in the argv array.
 * @param[in] argv Array of strings. The first string is the name of
 *  the service and subsequent strings are passed by the process
 *  that called the StartService function to start the service.
 *
 */
void WINAPI
service_main(unsigned long argc, _In_reads_(argc) wchar_t** argv)
{
    // Register the handler function for the service

    ebpf_service_status_handle = RegisterServiceCtrlHandler(SERVICE_NAME, service_control_handler);

    if (!ebpf_service_status_handle) {
        return;
    }

    // These SERVICE_STATUS members remain as set here
    ebpf_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ebpf_service_status.dwServiceSpecificExitCode = 0;

    // Report initial status to the SCM

    report_service_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    // Perform service-specific initialization and work.

    service_init(argc, argv);
}

void
service_report_event(_In_z_ wchar_t* function)
{
    UNREFERENCED_PARAMETER(function);
    return;
}

/**
 * @brief Called by SCM whenever a control code is sent to the service
 *  using the ControlService function.
 *
 * @param[in] ctrl control code.
 *
 */
void WINAPI
service_control_handler(unsigned long ctrl)
{
    // Handle the requested control code.

    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
        report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 0);
        // Signal the service to stop.
        SetEvent(ebpf_service_stop_event_handle);
        return;

    case SERVICE_CONTROL_INTERROGATE:
        break;

    default:
        break;
    }
}

void
report_service_status(unsigned long current_state, unsigned long win32_exit_code, unsigned long wait_hint)
{
    static unsigned long _checkpoint = 1;

    // Fill in the SERVICE_STATUS structure.

    ebpf_service_status.dwCurrentState = current_state;
    ebpf_service_status.dwWin32ExitCode = win32_exit_code;
    ebpf_service_status.dwWaitHint = wait_hint;

    if (current_state == SERVICE_START_PENDING) {
        ebpf_service_status.dwControlsAccepted = 0;
    } else {
        ebpf_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    }

    if ((current_state == SERVICE_RUNNING) || (current_state == SERVICE_STOPPED)) {
        ebpf_service_status.dwCheckPoint = 0;
    } else {
        ebpf_service_status.dwCheckPoint = _checkpoint++;
    }

    // Report the status of the service to the SCM.
    SetServiceStatus(ebpf_service_status_handle, &ebpf_service_status);
}

unsigned long
Initialize()
{
    unsigned long status;
    status = initialize_rpc_server();
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    status = ebpf_service_initialize();

Exit:
    return status;
}

void
Cleanup()
{
    shutdown_rpc_server();
    ebpf_service_cleanup();
    if (ebpf_service_stop_event_handle) {
        CloseHandle(ebpf_service_stop_event_handle);
    }
}

/**
 * @brief The service code.
 *
 * @param[in] argc Number of arguments in the argv array.
 * @param[in] argv Array of strings. The first string is the name of
 *  the service and subsequent strings are passed by the process
 *  that called the StartService function to start the service.
 *
 */
void
service_init(unsigned long argc, _In_reads_(argc) wchar_t** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    unsigned long status = NO_ERROR;

    // Create an event. The control handler function, service_control_handler,
    // signals this event when it receives the stop control code.
    ebpf_service_stop_event_handle = CreateEvent(
        nullptr,  // default security attributes
        true,     // manual reset event
        false,    // not signaled
        nullptr); // no name

    if (ebpf_service_stop_event_handle == nullptr) {
        report_service_status(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }

    status = Initialize();
    if (status != NO_ERROR) {
        Cleanup();
        report_service_status(SERVICE_STOPPED, status, 0);
        return;
    }

    // Report running status when initialization is complete.
    report_service_status(SERVICE_RUNNING, NO_ERROR, 0);

    // Check whether to stop the service.
    WaitForSingleObject(ebpf_service_stop_event_handle, INFINITE);

    Cleanup();

    report_service_status(SERVICE_STOPPED, NO_ERROR, 0);
    return;
}
