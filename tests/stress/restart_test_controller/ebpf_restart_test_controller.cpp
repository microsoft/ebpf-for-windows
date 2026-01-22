// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Standalone controller for eBPF core restart stress test.
 *
 * This executable does NOT load ebpfapi.dll, allowing it to test driver restart scenarios
 * without holding a reference to the driver itself. It coordinates child processes that
 * do load ebpfapi.dll to create test conditions.
 */

#include <windows.h>
#include <iostream>
#include <string>

namespace {
struct unique_handle
{
    unique_handle() = default;
    explicit unique_handle(HANDLE handle) : _handle(handle) {}
    ~unique_handle() { reset(); }

    unique_handle(const unique_handle&) = delete;
    unique_handle&
    operator=(const unique_handle&) = delete;

    unique_handle(unique_handle&& other) noexcept : _handle(other._handle) { other._handle = nullptr; }
    unique_handle&
    operator=(unique_handle&& other) noexcept
    {
        if (this != &other) {
            reset();
            _handle = other._handle;
            other._handle = nullptr;
        }
        return *this;
    }

    void
    reset(HANDLE handle = nullptr) noexcept
    {
        if (_handle != nullptr && _handle != INVALID_HANDLE_VALUE) {
            CloseHandle(_handle);
        }
        _handle = handle;
    }

    HANDLE
    get() const noexcept { return _handle; }

    HANDLE
    release() noexcept
    {
        HANDLE handle = _handle;
        _handle = nullptr;
        return handle;
    }

    explicit
    operator bool() const noexcept
    {
        return _handle != nullptr && _handle != INVALID_HANDLE_VALUE;
    }

  private:
    HANDLE _handle{nullptr};
};

struct unique_sc_handle
{
    unique_sc_handle() = default;
    explicit unique_sc_handle(SC_HANDLE handle) : _handle(handle) {}
    ~unique_sc_handle() { reset(); }

    unique_sc_handle(const unique_sc_handle&) = delete;
    unique_sc_handle&
    operator=(const unique_sc_handle&) = delete;

    unique_sc_handle(unique_sc_handle&& other) noexcept : _handle(other._handle) { other._handle = nullptr; }
    unique_sc_handle&
    operator=(unique_sc_handle&& other) noexcept
    {
        if (this != &other) {
            reset();
            _handle = other._handle;
            other._handle = nullptr;
        }
        return *this;
    }

    void
    reset(SC_HANDLE handle = nullptr) noexcept
    {
        if (_handle != nullptr) {
            CloseServiceHandle(_handle);
        }
        _handle = handle;
    }

    SC_HANDLE
    get() const noexcept { return _handle; }

    explicit
    operator bool() const noexcept
    {
        return _handle != nullptr;
    }

  private:
    SC_HANDLE _handle{nullptr};
};
} // namespace

// Signal names for IPC with child process.
#define SIGNAL_READY_HANDLES_OPEN "Global\\EBPF_RESTART_TEST_HANDLES_OPEN"
#define SIGNAL_READY_PINNED_OBJECTS "Global\\EBPF_RESTART_TEST_PINNED_OBJECTS"
#define SIGNAL_CONTROLLER_DONE "Global\\EBPF_RESTART_TEST_CONTROLLER_DONE"

// Helper function to wait for a named event with timeout
static bool
wait_for_child_signal(const char* signal_name, DWORD timeout_ms = 30000)
{
    ULONGLONG start_tick = GetTickCount64();
    unique_handle event;

    // Retry until the helper-created event exists or timeout expires.
    while (true) {
        event.reset(OpenEventA(SYNCHRONIZE, FALSE, signal_name));
        if (event) {
            break;
        }

        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_INVALID_NAME) {
            ULONGLONG elapsed = GetTickCount64() - start_tick;
            if (elapsed >= timeout_ms) {
                std::cerr << "Timeout waiting for event to be created: " << signal_name << std::endl;
                return false;
            }
            Sleep(100);
            continue;
        }

        std::cerr << "Failed to open event: " << signal_name << ", error: " << error << std::endl;
        return false;
    }

    ULONGLONG elapsed = GetTickCount64() - start_tick;
    DWORD remaining_timeout = (elapsed >= timeout_ms) ? 0 : (DWORD)(timeout_ms - elapsed);

    DWORD result = WaitForSingleObject(event.get(), remaining_timeout);

    if (result == WAIT_OBJECT_0) {
        std::cout << "Received signal: " << signal_name << std::endl;
        return true;
    } else if (result == WAIT_TIMEOUT) {
        std::cerr << "Timeout waiting for signal: " << signal_name << std::endl;
        return false;
    } else {
        std::cerr << "Error waiting for signal: " << signal_name << ", error: " << GetLastError() << std::endl;
        return false;
    }
}

// Helper function to signal the child process
static void
signal_child_done()
{
    unique_handle event(CreateEventA(nullptr, TRUE, FALSE, SIGNAL_CONTROLLER_DONE));
    if (!event) {
        std::cerr << "Failed to create controller done event, error: " << GetLastError() << std::endl;
        return;
    }
    SetEvent(event.get());
}

// Helper function to spawn child process
static HANDLE
spawn_child_process(const std::string& mode, PROCESS_INFORMATION& pi)
{
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);

    // Get the path to the helper executable (should be in the same directory as the controller)
    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    std::string exe_dir = exe_path;
    size_t last_slash = exe_dir.find_last_of("\\/");
    if (last_slash != std::string::npos) {
        exe_dir = exe_dir.substr(0, last_slash);
    }

    std::string command_line = exe_dir + "\\ebpf_restart_test_helper.exe " + mode;
    std::cout << "Spawning child process: " << command_line << std::endl;

    if (!CreateProcessA(
            nullptr, const_cast<char*>(command_line.c_str()), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to spawn child process, error: " << GetLastError() << std::endl;
        return nullptr;
    }

    std::cout << "Child process spawned with PID: " << pi.dwProcessId << std::endl;
    return pi.hProcess;
}

// Helper function to attempt to stop the ebpfcore driver
static DWORD
attempt_stop_ebpfcore()
{
    unique_sc_handle scm(OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        DWORD error = GetLastError();
        std::cerr << "Failed to open SCM, error: " << error << std::endl;
        return error;
    }

    unique_sc_handle service(OpenServiceW(scm.get(), L"ebpfcore", SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!service) {
        DWORD error = GetLastError();
        std::cerr << "Failed to open ebpfcore service, error: " << error << std::endl;
        return error;
    }

    SERVICE_STATUS status;
    if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &status)) {
        DWORD error = GetLastError();
        std::cout << "Failed to stop ebpfcore service, error: " << error << std::endl;
        return error;
    }

    // Wait for service to stop
    for (int i = 0; i < 10; i++) {
        if (!QueryServiceStatus(service.get(), &status)) {
            DWORD error = GetLastError();
            std::cerr << "Failed to query service status, error: " << error << std::endl;
            return error;
        }

        if (status.dwCurrentState == SERVICE_STOPPED) {
            std::cout << "ebpfcore service stopped successfully" << std::endl;
            return 0;
        }

        Sleep(500);
    }

    std::cerr << "Timeout waiting for ebpfcore service to stop" << std::endl;
    return ERROR_SERVICE_REQUEST_TIMEOUT;
}

// Helper function to start the ebpfcore driver
static DWORD
start_ebpfcore()
{
    unique_sc_handle scm(OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        DWORD error = GetLastError();
        std::cerr << "Failed to open SCM, error: " << error << std::endl;
        return error;
    }

    unique_sc_handle service(OpenServiceW(scm.get(), L"ebpfcore", SERVICE_START | SERVICE_QUERY_STATUS));
    if (!service) {
        DWORD error = GetLastError();
        std::cerr << "Failed to open ebpfcore service, error: " << error << std::endl;
        return error;
    }

    if (!StartService(service.get(), 0, nullptr)) {
        DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            std::cerr << "Failed to start ebpfcore service, error: " << error << std::endl;
            return error;
        }
    }

    // Wait for service to start
    SERVICE_STATUS status;
    for (int i = 0; i < 10; i++) {
        if (!QueryServiceStatus(service.get(), &status)) {
            DWORD error = GetLastError();
            std::cerr << "Failed to query service status, error: " << error << std::endl;
            return error;
        }

        if (status.dwCurrentState == SERVICE_RUNNING) {
            std::cout << "ebpfcore service started successfully" << std::endl;
            return 0;
        }

        Sleep(500);
    }

    std::cerr << "Timeout waiting for ebpfcore service to start" << std::endl;
    return ERROR_SERVICE_REQUEST_TIMEOUT;
}

int
main(int argc, char* argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    std::cout << "===== eBPF Core Restart Stress Test Controller =====" << std::endl;
    std::cout << "This controller does NOT load ebpfapi.dll to avoid holding driver references." << std::endl;
    std::cout << std::endl;

    int exit_code = 0;

    // Test 1: Stop with open handles (should fail)
    std::cout << "Test 1: Attempting to stop ebpfcore with child process holding open handles..." << std::endl;
    {
        PROCESS_INFORMATION pi = {0};
        unique_handle child_process(spawn_child_process("open-handles", pi));
        unique_handle child_thread(pi.hThread);
        pi.hProcess = nullptr;
        pi.hThread = nullptr;
        if (!child_process) {
            std::cerr << "FAIL: Could not spawn child process" << std::endl;
            return 1;
        }

        // Wait for child to signal it has handles open
        if (!wait_for_child_signal(SIGNAL_READY_HANDLES_OPEN)) {
            std::cerr << "FAIL: Did not receive signal from child" << std::endl;
            TerminateProcess(child_process.get(), 1);
            return 1;
        }

        // Try to stop ebpfcore - this should fail because the child has open handles
        DWORD stop_result = attempt_stop_ebpfcore();
        std::cout << "Stop result with open handles: " << stop_result << std::endl;

        // We expect the stop to fail (non-zero result)
        if (stop_result == 0) {
            std::cerr << "WARNING: ebpfcore stopped successfully despite open handles - this may indicate a regression!"
                      << std::endl;
            exit_code = 1;
        } else {
            std::cout << "PASS: Stop correctly failed with error code: " << stop_result << std::endl;
        }

        // Signal child to exit
        signal_child_done();

        // Wait for child to exit
        DWORD wait_result = WaitForSingleObject(child_process.get(), 5000);
        if (wait_result == WAIT_OBJECT_0) {
            std::cout << "Child process exited" << std::endl;
        } else if (wait_result == WAIT_TIMEOUT) {
            std::cerr << "WARNING: Child process did not exit within timeout; terminating" << std::endl;
            TerminateProcess(child_process.get(), 1);
            WaitForSingleObject(child_process.get(), INFINITE);
        } else if (wait_result == WAIT_FAILED) {
            std::cerr << "ERROR: WaitForSingleObject failed for child process, error: " << GetLastError() << std::endl;
        }
    }

    // Test 2: Stop after child exits (should succeed or fail gracefully)
    std::cout << std::endl
              << "Test 2: Attempting to stop ebpfcore after child exits with no pinned objects..." << std::endl;
    {
        // Sleep briefly to ensure handles are fully released
        Sleep(1000);

        DWORD stop_result = attempt_stop_ebpfcore();
        std::cout << "Stop result after child exit: " << stop_result << std::endl;

        if (stop_result != 0) {
            std::cout << "INFO: Failed to stop ebpfcore after child exited, error: " << stop_result << std::endl;
            std::cout << "Note: This may be expected if other processes (like the eBPF service) are holding references "
                         "to ebpfcore"
                      << std::endl;
        } else {
            std::cout << "PASS: ebpfcore stopped successfully after child exit" << std::endl;

            // Restart ebpfcore
            DWORD start_result = start_ebpfcore();
            if (start_result != 0) {
                std::cerr << "FAIL: Could not restart ebpfcore, error: " << start_result << std::endl;
                return 1;
            }
            std::cout << "PASS: ebpfcore restarted successfully" << std::endl;

            // Brief sleep to let the driver stabilize
            Sleep(2000);
        }
    }

    // Test 3: Pinned objects test
    std::cout << std::endl << "Test 3: Testing behavior with pinned objects..." << std::endl;
    {
        PROCESS_INFORMATION pi = {0};
        unique_handle child_process(spawn_child_process("pin-objects", pi));
        unique_handle child_thread(pi.hThread);
        pi.hProcess = nullptr;
        pi.hThread = nullptr;
        if (!child_process) {
            std::cerr << "FAIL: Could not spawn child process" << std::endl;
            return 1;
        }

        // Wait for child to signal it has pinned objects and released handles
        if (!wait_for_child_signal(SIGNAL_READY_PINNED_OBJECTS)) {
            std::cerr << "FAIL: Did not receive signal from child" << std::endl;
            TerminateProcess(child_process.get(), 1);
            return 1;
        }

        // Wait for child to exit (it exits immediately after pinning)
        DWORD wait_result = WaitForSingleObject(child_process.get(), 5000);
        if (wait_result == WAIT_OBJECT_0) {
            std::cout << "Child process exited" << std::endl;
        } else if (wait_result == WAIT_TIMEOUT) {
            std::cerr << "WARNING: Child process did not exit within timeout; terminating" << std::endl;
            TerminateProcess(child_process.get(), 1);
            WaitForSingleObject(child_process.get(), INFINITE);
        } else if (wait_result == WAIT_FAILED) {
            std::cerr << "ERROR: WaitForSingleObject failed for child process, error: " << GetLastError() << std::endl;
        }

        std::cout << "Child process exited with pinned objects remaining" << std::endl;

        // Sleep briefly
        Sleep(1000);

        // Try to stop ebpfcore with pinned objects present
        DWORD stop_result = attempt_stop_ebpfcore();
        std::cout << "Stop result with pinned objects: " << stop_result << std::endl;

        // The behavior here is implementation-defined:
        // - If stop succeeds, pinned objects may be cleaned up by the driver
        // - If stop fails, pinned objects are preventing driver unload
        // Both behaviors are acceptable and should be documented
        if (stop_result == 0) {
            std::cout << "INFO: ebpfcore stopped successfully with pinned objects (objects may have been cleaned up)"
                      << std::endl;

            // Restart
            DWORD start_result = start_ebpfcore();
            if (start_result != 0) {
                std::cerr << "FAIL: Could not restart ebpfcore, error: " << start_result << std::endl;
                return 1;
            }
            std::cout << "PASS: ebpfcore restarted successfully" << std::endl;
            Sleep(2000);
        } else {
            std::cout << "INFO: ebpfcore cannot be stopped with pinned objects present (error: " << stop_result << ")"
                      << std::endl;

            // Unpin the objects
            PROCESS_INFORMATION pi2 = {0};
            unique_handle unpin_process(spawn_child_process("unpin-objects", pi2));
            unique_handle unpin_thread(pi2.hThread);
            pi2.hProcess = nullptr;
            pi2.hThread = nullptr;
            if (!unpin_process) {
                std::cerr << "FAIL: Could not spawn unpin process" << std::endl;
                return 1;
            }

            DWORD wait_result_unpin = WaitForSingleObject(unpin_process.get(), 10000);
            if (wait_result_unpin == WAIT_OBJECT_0) {
                // Success path; nothing else to do.
            } else if (wait_result_unpin == WAIT_TIMEOUT) {
                std::cerr << "FAIL: Timeout waiting for unpin process to exit" << std::endl;
                return 1;
            } else if (wait_result_unpin == WAIT_FAILED) {
                std::cerr << "FAIL: Error waiting for unpin process, error: " << GetLastError() << std::endl;
                return 1;
            } else {
                std::cerr << "FAIL: Unexpected wait result for unpin process: " << wait_result_unpin << std::endl;
                return 1;
            }

            std::cout << "Objects unpinned" << std::endl;
            Sleep(1000);

            // Try to stop again
            DWORD stop_result2 = attempt_stop_ebpfcore();
            if (stop_result2 == 0) {
                std::cout << "PASS: ebpfcore stopped successfully after unpinning objects" << std::endl;

                // Restart
                DWORD start_result = start_ebpfcore();
                if (start_result != 0) {
                    std::cerr << "FAIL: Could not restart ebpfcore, error: " << start_result << std::endl;
                    return 1;
                }
                std::cout << "PASS: ebpfcore restarted successfully" << std::endl;
                Sleep(2000);
            } else {
                std::cout << "INFO: ebpfcore still cannot be stopped (error: " << stop_result2
                          << "), likely due to other processes" << std::endl;
            }
        }
    }

    std::cout << std::endl << "===== Test Controller Completed =====" << std::endl;
    std::cout << "Exit code: " << exit_code << std::endl;
    return exit_code;
}
