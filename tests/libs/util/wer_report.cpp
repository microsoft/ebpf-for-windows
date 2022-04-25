// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <errorrep.h>
#include <stdexcept>
#include <string>
#include <werapi.h>

#pragma comment(lib, "wer.lib")
/**
 * @brief Class to automatically capture WER Report / Triage crash dump on fatal application exception.
 * Exceptions are only logged if the environment variable EBPF_ENABLE_WER_REPORT is set to "yes".
 *
 */
class _wer_report
{
  public:
    _wer_report() : vectored_exception_handler_handle(nullptr)
    {
        unsigned long guaranteed_stack_size = static_cast<unsigned long>(minimum_stack_size_for_wer);
        char* buffer = nullptr;
        size_t size = 0;
        _dupenv_s(&buffer, &size, environment_variable_name);
        if (size == 0 || !buffer || _stricmp(environment_variable_value, buffer) != 0) {
            free(buffer);
            return;
        }
        free(buffer);

        if (!SetThreadStackGuarantee(&guaranteed_stack_size)) {
            throw std::runtime_error("SetThreadStackGuarantee failed");
        }
        vectored_exception_handler_handle = AddVectoredExceptionHandler(TRUE, _wer_report::vectored_exception_handler);
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
    static constexpr unsigned long fatal_exceptions[] = {
        EXCEPTION_ILLEGAL_INSTRUCTION,
        EXCEPTION_STACK_OVERFLOW,
        EXCEPTION_ACCESS_VIOLATION,
        EXCEPTION_INT_DIVIDE_BY_ZERO};

    static constexpr size_t minimum_stack_size_for_wer = 32 * 1024;

    static LONG
    vectored_exception_handler(_EXCEPTION_POINTERS* exception_info)
    {
        HREPORT report_handle;
        WER_EXCEPTION_INFORMATION exception_information{exception_info, TRUE};
        HRESULT hr;
        hr = WerReportCreate(wer_event_type, WerReportApplicationCrash, nullptr, &report_handle);
        if (FAILED(hr)) {
            fprintf(stderr, "WerReportCreate failed with erorr %X\n", hr);
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
            fprintf(stderr, "WerReportAddDump failed with erorr %X\n", hr);
            return EXCEPTION_CONTINUE_SEARCH;
        }
        hr = WerReportSubmit(report_handle, WerConsentApproved, 0, nullptr);
        if (FAILED(hr)) {
            fprintf(stderr, "WerReportSubmit failed with erorr %X\n", hr);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        fprintf(stderr, "WerReportSubmit succeeded\n");
        return EXCEPTION_CONTINUE_SEARCH;
    }
    void* vectored_exception_handler_handle;
} _wer_report_singleton;