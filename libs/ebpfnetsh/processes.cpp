// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define EBPF_DEVICE_NAME L"\\Device\\EbpfIoDevice"
#include "processes.h"

#include <iomanip>
#include <iostream>

#define PSAPI_VERSION 1
#include <processsnapshot.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <stdio.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

#define ObjectNameInformation ((OBJECT_INFORMATION_CLASS)1)
typedef struct
{
    UNICODE_STRING Name;
    WCHAR NameBuffer[1];
} OBJECT_NAME_INFORMATION;

typedef struct
{
    HANDLE target_handle;
    WCHAR name[1024];
} query_name_param_t;

// Get the object name associated with a target handle.
static DWORD WINAPI
_query_name_thread_proc(_In_ void* parameter)
{
    query_name_param_t* param = (query_name_param_t*)parameter;

    char buffer[1024];
    ULONG buffer_size = sizeof(buffer);
    NTSTATUS status;
    OBJECT_NAME_INFORMATION* object_name_info = (OBJECT_NAME_INFORMATION*)buffer;
    status = NtQueryObject(param->target_handle, ObjectNameInformation, object_name_info, buffer_size, nullptr);
    if (NT_SUCCESS(status) && (object_name_info->Name.Length > 0)) {
        if (object_name_info->Name.Length >= sizeof(param->name)) {
            param->name[0] = 0;
            return 1;
        }
        memcpy(param->name, object_name_info->Name.Buffer, object_name_info->Name.Length);
        param->name[object_name_info->Name.Length / sizeof(WCHAR)] = 0;
    } else {
        param->name[0] = 0;
    }
    return 0;
}

static void
_print_process_info(HANDLE process_handle)
{
    WCHAR process_name[MAX_PATH];
    (void)GetModuleBaseName(process_handle, nullptr, process_name, sizeof(process_name) / sizeof(*process_name));
    std::wcout << std::right << std::setw(5) << GetProcessId(process_handle) << "  " << std::wstring(process_name)
               << std::endl;
}

// Print info on handle if we can get the name of the object it references.
static void
_print_handle_info(HANDLE process_handle, HANDLE other_handle)
{
    // Duplicate the handle into the local process so we can query it.
    HANDLE local_handle;
    if (!DuplicateHandle(
            process_handle, other_handle, GetCurrentProcess(), &local_handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        // Some handle types cannot be duplicated. This is ok, since the handles we're looking for can be
        // duplicated.  Also, we can't duplicate handles in some system security processes. This is ok,
        // we just can't detect whether they have handles open of the type we're looking for.
        return;
    }

    // Get type information.
    query_name_param_t param = {};
    char buffer[1024];
    ULONG buffer_size = sizeof(buffer);
    PUBLIC_OBJECT_TYPE_INFORMATION object_type_info;
    ULONG bytes_needed = 0;
    HANDLE thread;
    NTSTATUS status = NtQueryObject(local_handle, ObjectTypeInformation, buffer, buffer_size, &bytes_needed);
    if (!NT_SUCCESS(status)) {
        goto Done;
    }
    memcpy(&object_type_info, buffer, sizeof(object_type_info));

    // eBPF handles are always of type "File".
    if (wcscmp(object_type_info.TypeName.Buffer, L"File") != 0) {
        goto Done;
    }

    // Set a 200ms timeout for querying object name after which we just give up.
    // In the future, we could optimize this by reusing the same worker thread each time
    // instead of creating a new one per handle
#define TIMEOUT_IN_MS 200
    param.target_handle = local_handle;
    thread = CreateThread(nullptr, 0, _query_name_thread_proc, &param, 0, nullptr);
    if (!thread) {
        goto Done;
    }
    if (WaitForSingleObject(thread, TIMEOUT_IN_MS) == WAIT_TIMEOUT) {
#pragma warning(suppress : 6258) // Using TerminateThread does not allow proper thread clean up.
        TerminateThread(thread, 1);
    }
    CloseHandle(thread);
    if (wcsstr(param.name, EBPF_DEVICE_NAME) != nullptr) {
        _print_process_info(process_handle);
    }
Done:
    CloseHandle(local_handle);
}

static void
_walk_all_handles_for_process(HANDLE process_handle)
{
    HPSS snapshot_handle = nullptr;
    PSS_CAPTURE_FLAGS capture_flags =
        PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION;
    DWORD result = PssCaptureSnapshot(process_handle, capture_flags, 0, &snapshot_handle);
    if (result != ERROR_SUCCESS) {
        return;
    }

    PSS_PROCESS_INFORMATION process_information;
    result = PssQuerySnapshot(
        snapshot_handle, PSS_QUERY_PROCESS_INFORMATION, &process_information, sizeof(process_information));

    PSS_HANDLE_INFORMATION pss_handle_information;
    result = PssQuerySnapshot(
        snapshot_handle, PSS_QUERY_HANDLE_INFORMATION, &pss_handle_information, sizeof(pss_handle_information));

    HPSSWALK walk_marker_handle;
    result = PssWalkMarkerCreate(nullptr, &walk_marker_handle);
    if (result == ERROR_SUCCESS) {
        PSS_HANDLE_ENTRY handle_entry;
        for (;;) {
            result = PssWalkSnapshot(
                snapshot_handle, PSS_WALK_HANDLES, walk_marker_handle, &handle_entry, sizeof(handle_entry));
            if (result != ERROR_SUCCESS) {
                break;
            }

            if (handle_entry.ObjectType != 0) {
                // Ignore thread, semaphore, event, etc. handles.
                continue;
            }

            _print_handle_info(process_handle, handle_entry.Handle);
        }

        PssWalkMarkerFree(walk_marker_handle);
    }
    PssFreeSnapshot(process_handle, snapshot_handle);
}

// Walk all handles for a given process looking for eBPF handles.
static int
_open_process_and_walk_handles(DWORD process_id)
{
    WCHAR process_name[MAX_PATH] = L"<unknown>";

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (process_handle == nullptr) {
        return 1;
    }

    _walk_all_handles_for_process(process_handle);

    CloseHandle(process_handle);
    return 0;
}

static bool
_is_elevated()
{
    TOKEN_ELEVATION token_elevation = {0};
    DWORD return_length = 0;

    if (!GetTokenInformation(
            GetCurrentProcessToken(), TokenElevation, &token_elevation, sizeof(token_elevation), &return_length)) {
        return 0;
    }

    return token_elevation.TokenIsElevated;
}

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_show_processes(
    IN LPCWSTR machine,
    _Inout_updates_(argc) LPWSTR* argv,
    IN DWORD current_index,
    IN DWORD argc,
    IN DWORD flags,
    IN LPCVOID data,
    OUT BOOL* done)
{
    UNREFERENCED_PARAMETER(argv);
    UNREFERENCED_PARAMETER(current_index);
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    // Check whether we are running elevated.
    if (!_is_elevated()) {
        std::cout << "This command requires running as Administrator" << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    }

    DWORD max_processes = 512;
    DWORD bytes_used;
    DWORD* processes = nullptr;
    DWORD process_count;

    // Get the list of process identifiers.
    do {
        max_processes *= 2;
        delete[] processes;
        processes = new DWORD[max_processes];
        if (!EnumProcesses(processes, max_processes * sizeof(DWORD), &bytes_used)) {
            return GetLastError();
        }

        // Calculate how many process identifiers were returned.
        process_count = bytes_used / sizeof(DWORD);
    } while (process_count == max_processes);

    std::cout << std::endl;
    std::cout << "  PID  Name" << std::endl;
    std::cout << "=====  ==============" << std::endl;

    // Walk all handles for each process looking for eBPF handles.
    for (DWORD i = 0; i < process_count; i++) {
        if (processes[i] != 0) {
            _open_process_and_walk_handles(processes[i]);
        }
    }

    delete[] processes;
    return NO_ERROR;
}