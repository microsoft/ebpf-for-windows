/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "pch.h"

#define SERVICE_NAME TEXT("eBPFService")

SERVICE_STATUS          _service_status;
SERVICE_STATUS_HANDLE   _service_status_handle;
HANDLE                  _service_stop_event_handle = NULL;

VOID WINAPI service_control_handler(DWORD dwCtrl);
VOID service_report_event(LPTSTR function);
VOID report_service_status(
    DWORD current_state,
    DWORD win32exitcode,
    DWORD wait_hint);
VOID service_init(DWORD argc, LPTSTR* argv);

VOID WINAPI service_main(DWORD argc, LPTSTR* argv);
VOID service_install();

DWORD rpcStatus = 0;

DWORD initialize_rpc_server();
void shutdown_rpc_server();

int
__cdecl wmain(
    __in ULONG argc,
    __in_ecount(argc) PWSTR* argv
)
{
    SERVICE_TABLE_ENTRY dispatch_table[] =
    {
        { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)service_main },
        { NULL, NULL }
    };

    // If command-line parameter is "install", install the service. 
    // Otherwise, the service is probably being started by the SCM.

    if (argc > 1)
    {
        if (wcscmp(argv[1], L"install") == 0)
        {
            service_install();
            return -1;
        }
    }

    // This call returns when the service has stopped. 
    // The process should simply terminate when the call returns.

    if (!StartServiceCtrlDispatcher(dispatch_table))
    {
        service_report_event((LPWSTR)L"StartServiceCtrlDispatcher");
    }

    return 0;
}

//
// Purpose: 
//   Installs a service in the SCM database
//
// Parameters:
//   None
// 
// Return value:
//   None
//
VOID service_install()
{
    SC_HANDLE scmanager;
    SC_HANDLE service;
    TCHAR path[MAX_PATH];

    if (!GetModuleFileName(NULL, path, MAX_PATH))
    {
        // printf("Cannot install service (%d)\n", GetLastError());
        return;
    }

    // Get a handle to the SCM database. 

    scmanager = OpenSCManager(
        NULL,                    // local computer
        NULL,                    // ServicesActive database 
        SC_MANAGER_ALL_ACCESS);  // full access rights 

    if (NULL == scmanager)
    {
        // printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }

    // Create the service

    service = CreateService(
        scmanager,                 // SCM database 
        SERVICE_NAME,              // name of service 
        SERVICE_NAME,              // service name to display 
        SERVICE_ALL_ACCESS,        // desired access 
        SERVICE_WIN32_OWN_PROCESS, // service type 
        SERVICE_DEMAND_START,      // start type 
        SERVICE_ERROR_NORMAL,      // error control type 
        path  ,                    // path to service's binary 
        NULL,                      // no load ordering group 
        NULL,                      // no tag identifier 
        NULL,                      // no dependencies 
        NULL,                      // LocalSystem account 
        NULL);                     // no password 

    if (service == NULL)
    {
        // printf("CreateService failed (%d)\n", GetLastError());
        CloseServiceHandle(scmanager);
        return;
    }
    // else printf("Service installed successfully\n");

    CloseServiceHandle(service);
    CloseServiceHandle(scmanager);
}

//
// Purpose: 
//   Entry point for the service
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
// 
// Return value:
//   None.
//
VOID WINAPI service_main(DWORD argc, LPTSTR* argv)
{
    // Register the handler function for the service

    _service_status_handle = RegisterServiceCtrlHandler(
        SERVICE_NAME,
        service_control_handler);

    if (!_service_status_handle)
    {
        // SvcReportEvent(TEXT("RegisterServiceCtrlHandler"));
        return;
    }

    // These SERVICE_STATUS members remain as set here
    _service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    _service_status.dwServiceSpecificExitCode = 0;

    // Report initial status to the SCM

    report_service_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    // Perform service-specific initialization and work.

    service_init(argc, argv);
}

VOID service_report_event(LPTSTR function)
{
    UNREFERENCED_PARAMETER(function);
    return;
}

//
// Purpose: 
//   Called by SCM whenever a control code is sent to the service
//   using the ControlService function.
//
// Parameters:
//   dwCtrl - control code
// 
// Return value:
//   None
//
VOID WINAPI service_control_handler(DWORD ctrl)
{
    // Handle the requested control code. 

    switch (ctrl)
    {
    case SERVICE_CONTROL_STOP:
        report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 0);
        // Signal the service to stop.
        SetEvent(_service_stop_event_handle);
        return;

    case SERVICE_CONTROL_INTERROGATE:
        break;

    default:
        break;
    }

}

VOID report_service_status(
    DWORD current_state,
    DWORD win32exitcode,
    DWORD wait_hint)
{
    static DWORD checkpoint = 1;

    // Fill in the SERVICE_STATUS structure.

    _service_status.dwCurrentState = current_state;
    _service_status.dwWin32ExitCode = win32exitcode;
    _service_status.dwWaitHint = wait_hint;

    if (current_state == SERVICE_START_PENDING)
        _service_status.dwControlsAccepted = 0;
    else _service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if ((current_state == SERVICE_RUNNING) ||
        (current_state == SERVICE_STOPPED))
        _service_status.dwCheckPoint = 0;
    else _service_status.dwCheckPoint = checkpoint++;

    // Report the status of the service to the SCM.
    SetServiceStatus(_service_status_handle, &_service_status);
}

DWORD Initialize()
{
    DWORD status;
    status = initialize_rpc_server();

    return status;
}

VOID Cleanup()
{
    shutdown_rpc_server();
    if (_service_stop_event_handle)
    {
        CloseHandle(_service_stop_event_handle);
    }
}

//
// Purpose: 
//   The service code
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
// 
// Return value:
//   None
//
VOID service_init(DWORD argc, LPTSTR* argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    DWORD status = NO_ERROR;

    // Create an event. The control handler function, service_control_handler,
    // signals this event when it receives the stop control code.
    _service_stop_event_handle = CreateEvent(
        NULL,    // default security attributes
        TRUE,    // manual reset event
        FALSE,   // not signaled
        NULL);   // no name

    if (_service_stop_event_handle == NULL)
    {
        report_service_status(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }

    status = Initialize();
    if (status != NO_ERROR)
    {
        Cleanup();
        report_service_status(SERVICE_STOPPED, status, 0);
        return;
    }

    // Report running status when initialization is complete.
    report_service_status(SERVICE_RUNNING, NO_ERROR, 0);

    while (1)
    {
        // Check whether to stop the service.
        WaitForSingleObject(_service_stop_event_handle, INFINITE);

        Cleanup();

        report_service_status(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
}
