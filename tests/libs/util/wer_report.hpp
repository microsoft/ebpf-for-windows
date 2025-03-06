// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include <crtdbg.h>
#include <csignal>
#include <iostream>
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <errorrep.h>
#include <stdexcept>
#include <string>
#define VOID void
#include <werapi.h>

// Some of the NT_STATUS codes aren't defined in the user mode headers
// and are only defined in the kernel mode headers.
#if !defined(STATUS_HANDLE_NOT_CLOSABLE)
#define STATUS_HANDLE_NOT_CLOSABLE 0xC0000235L
#endif

#if !defined(STATUS_INSTRUCTION_MISALIGNMENT)
#define STATUS_INSTRUCTION_MISALIGNMENT 0xC00000AAL
#endif

#if !defined(STATUS_POSSIBLE_DEADLOCK)
#define STATUS_POSSIBLE_DEADLOCK 0xC0000194L
#endif

#pragma comment(lib, "wer.lib")

/**
 * @brief Class to automatically capture WER Report / Triage crash dump on fatal application exception.
 * Exceptions are only logged if the environment variable EBPF_ENABLE_WER_REPORT is set to "yes".
 *
 */
class _wer_report
{
  public:
    bool enabled = false;
    _wer_report() : vectored_exception_handler_handle(nullptr)
    {
        unsigned long guaranteed_stack_size = static_cast<unsigned long>(minimum_stack_size_for_wer);
        char* buffer = nullptr;
        size_t size = 0;

        // Check if the EBPF_ENABLE_WER_REPORT is set to "yes".
        _dupenv_s(&buffer, &size, environment_variable_name);
        if (size == 0 || !buffer || _stricmp(environment_variable_value, buffer) != 0) {
            free(buffer);
            return;
        }
        free(buffer);

        // Redirect error output to STDERR so that it is captured in the console
        // when running in CI/CD.
        _set_error_mode(_OUT_TO_STDERR);

        // Add a hook to generate WER report on failed assertions and other
        //  failures raised by MSVC runtime.
        _CrtSetReportHook(_terminate_hook);

        // Add a hook to generate WER report on noexcept violations and other
        // cases where the CRT calls std::abort().
        signal(SIGABRT, signal_handler);

        // Reserve stack space for WER report generation.
        if (!SetThreadStackGuarantee(&guaranteed_stack_size)) {
            throw std::runtime_error("SetThreadStackGuarantee failed");
        }

        // Add a vectored exception handler to generate WER report on unhandled
        // exceptions.
        vectored_exception_handler_handle = AddVectoredExceptionHandler(TRUE, _wer_report::vectored_exception_handler);
        enabled = true;
    }
    ~_wer_report()
    {
        if (vectored_exception_handler_handle)
            RemoveVectoredExceptionHandler(vectored_exception_handler_handle);
    }

  private:
    static constexpr const char environment_variable_name[] = "EBPF_ENABLE_WER_REPORT";
    static constexpr const char environment_variable_value[] = "yes";
    static constexpr const wchar_t wer_event_type[] = L"Test Application Crash";

    static int __CRTDECL
    _terminate_hook(int reportType, char* message, int* returnValue)
    {
        UNREFERENCED_PARAMETER(reportType);
        UNREFERENCED_PARAMETER(returnValue);

        std::cerr << message;
        std::cerr.flush();

        // Convert a CRT runtime error into a SEH exception.
        RaiseException(STATUS_ASSERTION_FAILURE, 0, 0, NULL);
        return 0;
    }

    static void __cdecl signal_handler(int)
    {
        // Convert a SIGABRT signal into a SEH exception.
        RaiseException(STATUS_ASSERTION_FAILURE, 0, 0, NULL);
    }

    static constexpr unsigned long fatal_exceptions[] = {
        STATUS_ACCESS_VIOLATION,
        STATUS_ASSERTION_FAILURE,
        STATUS_BREAKPOINT,
        STATUS_DATATYPE_MISALIGNMENT,
        STATUS_GUARD_PAGE_VIOLATION,
        STATUS_HANDLE_NOT_CLOSABLE,
        STATUS_HEAP_CORRUPTION,
        STATUS_ILLEGAL_INSTRUCTION,
        STATUS_IN_PAGE_ERROR,
        STATUS_INSTRUCTION_MISALIGNMENT,
        STATUS_POSSIBLE_DEADLOCK,
        STATUS_PRIVILEGED_INSTRUCTION,
        STATUS_REG_NAT_CONSUMPTION,
        STATUS_STACK_BUFFER_OVERRUN,
        STATUS_STACK_OVERFLOW,
    };

    static constexpr size_t minimum_stack_size_for_wer = 32 * 1024;

    static LONG
    vectored_exception_handler(_EXCEPTION_POINTERS* exception_info)
    {
        HREPORT report_handle;
        WER_EXCEPTION_INFORMATION exception_information{exception_info, TRUE};
        bool fatal = false;
        for (auto& code : fatal_exceptions) {
            if (exception_info->ExceptionRecord->ExceptionCode == code) {
                fatal = true;
                break;
            }
        }
        if (!fatal) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        HRESULT hr;
        hr = WerReportCreate(wer_event_type, WerReportApplicationCrash, nullptr, &report_handle);
        if (FAILED(hr)) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        hr = WerReportAddDump(
            report_handle,
            GetCurrentProcess(),
            GetCurrentThread(),
            WerDumpTypeHeapDump,
            &exception_information,
            nullptr,
            0);
        if (FAILED(hr)) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        hr = WerReportSubmit(report_handle, WerConsentApproved, 0, nullptr);
        if (FAILED(hr)) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }
    void* vectored_exception_handler_handle;
};

inline _wer_report _wer_report_singleton;
