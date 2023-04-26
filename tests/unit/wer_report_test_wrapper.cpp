// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _wer_report _wer_report_test
#define _ebpf_watchdog_timer _ebpf_watchdog_timer_test
#define AddVectoredExceptionHandler AddVectoredExceptionHandler_test
#define SetThreadStackGuarantee SetThreadStackGuarantee_test
#define RemoveVectoredExceptionHandler RemoveVectoredExceptionHandler_test
#define WerReportCreate WerReportCreate_test
#define WerReportAddDump WerReportAddDump_test
#define WerReportSubmit WerReportSubmit_test
#define WINBASEAPI

// Included first to ensure the overridden copy is the only one.
#include "ebpf_watchdog_timer.h"
#include "wer_report.hpp"

#undef _wer_report
#undef _ebpf_watchdog_timer_test
#undef AddVectoredExceptionHandler
#undef SetThreadStackGuarantee
#undef RemoveVectoredExceptionHandler
#undef WerReportCreate
#undef WerReportAddDump
#undef WerReportSubmit
#undef WINBASEAPI
#undef _dupenv_s

#include "catch_wrapper.hpp"

uint32_t _vectored_exception_handler_test = 1;

unsigned long AddVectoredExceptionHandler_test_first = 0;
PVECTORED_EXCEPTION_HANDLER AddVectoredExceptionHandler_test_handler = nullptr;

// Incorrect SAL required to match header.
_Ret_maybenull_ void*
AddVectoredExceptionHandler_test(_In_ unsigned long first, _In_ PVECTORED_EXCEPTION_HANDLER handler)
{
    AddVectoredExceptionHandler_test_first = first;
    AddVectoredExceptionHandler_test_handler = handler;
    return &_vectored_exception_handler_test;
}

unsigned long SetThreadStackGuarantee_test_stack_size_in_bytes = 0;

// Use BOOL to pass "SetThreadStackGuarantee"
// defined in windows "processthreadapi.h" file
BOOL
SetThreadStackGuarantee_test(_Inout_ unsigned long* stack_size_in_bytes)
{
    SetThreadStackGuarantee_test_stack_size_in_bytes = *stack_size_in_bytes;
    return TRUE;
}

unsigned long WINAPI
RemoveVectoredExceptionHandler_test(_In_ void* handle)
{
    UNREFERENCED_PARAMETER(handle);
    return 0;
}

uint32_t WerReportCreate_test_report_handle = 2;

bool WerReportCreate_test_fail = false;
bool WerReportCreate_test_called = false;

std::wstring WerReportCreate_test_expected_event_type = L"Test Application Crash";
WER_REPORT_TYPE WerReportCreate_test_expected_report_type = WerReportApplicationCrash;

// Incorrect SAL required to match header.
HRESULT
WINAPI
WerReportCreate_test(
    _In_ const wchar_t* event_type,
    _In_ WER_REPORT_TYPE report_type,
    _In_opt_ WER_REPORT_INFORMATION* report_information,
    _Out_ HREPORT* report_handle)
{
    REQUIRE(std::wstring(event_type) == WerReportCreate_test_expected_event_type);
    REQUIRE(report_type == WerReportCreate_test_expected_report_type);
    REQUIRE(report_information == nullptr);
    *report_handle = &WerReportCreate_test_report_handle;
    WerReportCreate_test_called = true;
    return !WerReportCreate_test_fail ? S_OK : E_FAIL;
}

bool WerReportAddDump_test_fail = false;
bool WerReportAddDump_test_called = false;

bool WerReportAddDump_test_expected_exception_param = true;

HRESULT
WINAPI
WerReportAddDump_test(
    _In_ HREPORT report_handle,
    _In_ HANDLE process,
    _In_opt_ HANDLE thread,
    _In_ WER_DUMP_TYPE dump_type,
    _In_opt_ WER_EXCEPTION_INFORMATION* exception_param,
    _In_opt_ WER_DUMP_CUSTOM_OPTIONS* dump_custom_options,
    _In_ unsigned long dwFlags)
{
    REQUIRE(report_handle == &WerReportCreate_test_report_handle);
    REQUIRE(process == GetCurrentProcess());
    REQUIRE(thread == GetCurrentThread());
    REQUIRE(dump_type == WerDumpTypeHeapDump);
    REQUIRE(((exception_param != nullptr) || !WerReportAddDump_test_expected_exception_param));
    REQUIRE(dump_custom_options == nullptr);
    REQUIRE(dwFlags == 0);
    WerReportAddDump_test_called = true;
    return !WerReportAddDump_test_fail ? S_OK : E_FAIL;
}

bool WerReportSubmit_test_fail = false;
bool WerReportSubmit_test_called = false;

HRESULT
WINAPI
WerReportSubmit_test(
    _In_ HREPORT report_handle,
    _In_ WER_CONSENT consent,
    _In_ unsigned long flags,
    _Out_opt_ WER_SUBMIT_RESULT* pSubmitResult)
{
    REQUIRE(report_handle == &WerReportCreate_test_report_handle);
    REQUIRE(consent == WerConsentApproved);
    REQUIRE(flags == 0);

    if (pSubmitResult) {
        *pSubmitResult = WerReportQueued;
    }
    WerReportSubmit_test_called = true;

    return !WerReportSubmit_test_fail ? S_OK : E_FAIL;
}

TEST_CASE("wer_report_started_shutdown", "[wer_report]")
{
    char* old_buffer = nullptr;
    size_t size = 0;
    _dupenv_s(&old_buffer, &size, "EBPF_ENABLE_WER_REPORT");
    _putenv_s("EBPF_ENABLE_WER_REPORT", "yes");
    {
        _wer_report_test _wer_report_test_singleton;
        REQUIRE(AddVectoredExceptionHandler_test_first);
        REQUIRE(AddVectoredExceptionHandler_test_handler != nullptr);
        REQUIRE(SetThreadStackGuarantee_test_stack_size_in_bytes == 32 * 1024);
    }

    if (old_buffer) {
        _putenv_s("EBPF_ENABLE_WER_REPORT", old_buffer);
    }
}

TEST_CASE("wer_report_fatal_exception", "[wer_report]")
{
    _EXCEPTION_RECORD exception_record{};
    CONTEXT exception_context{};
    _EXCEPTION_POINTERS exception_pointers{&exception_record, &exception_context};
    exception_pointers.ExceptionRecord->ExceptionCode = EXCEPTION_ACCESS_VIOLATION;

    WerReportCreate_test_fail = false;
    WerReportAddDump_test_fail = false;
    WerReportSubmit_test_fail = false;
    WerReportCreate_test_called = false;
    WerReportAddDump_test_called = false;
    WerReportSubmit_test_called = false;

    // Invoke the registered vectored exception handler.
    REQUIRE(AddVectoredExceptionHandler_test_handler(&exception_pointers) == EXCEPTION_CONTINUE_SEARCH);
    REQUIRE(WerReportCreate_test_called);
    REQUIRE(WerReportAddDump_test_called);
    REQUIRE(WerReportSubmit_test_called);
}

TEST_CASE("wer_report_non_fatal_exception", "[wer_report]")
{
    _EXCEPTION_RECORD exception_record{};
    CONTEXT exception_context{};
    _EXCEPTION_POINTERS exception_pointers{&exception_record, &exception_context};
    exception_pointers.ExceptionRecord->ExceptionCode = 0x12345678;

    WerReportCreate_test_fail = false;
    WerReportAddDump_test_fail = false;
    WerReportSubmit_test_fail = false;
    WerReportCreate_test_called = false;
    WerReportAddDump_test_called = false;
    WerReportSubmit_test_called = false;

    // Invoke the registered vectored exception handler.
    REQUIRE(AddVectoredExceptionHandler_test_handler(&exception_pointers) == EXCEPTION_CONTINUE_SEARCH);
    REQUIRE(!WerReportCreate_test_called);
    REQUIRE(!WerReportAddDump_test_called);
    REQUIRE(!WerReportSubmit_test_called);
}

TEST_CASE("wer_report_failure", "[wer_report]")
{
    _EXCEPTION_RECORD exception_record{};
    CONTEXT exception_context{};
    _EXCEPTION_POINTERS exception_pointers{&exception_record, &exception_context};
    exception_pointers.ExceptionRecord->ExceptionCode = EXCEPTION_ACCESS_VIOLATION;

    WerReportCreate_test_fail = true;
    WerReportAddDump_test_fail = false;
    WerReportSubmit_test_fail = false;
    WerReportCreate_test_called = false;
    WerReportAddDump_test_called = false;
    WerReportSubmit_test_called = false;

    // Fail WerReportCreate
    REQUIRE(AddVectoredExceptionHandler_test_handler(&exception_pointers) == EXCEPTION_CONTINUE_SEARCH);
    REQUIRE(WerReportCreate_test_called);
    REQUIRE(!WerReportAddDump_test_called);
    REQUIRE(!WerReportSubmit_test_called);

    WerReportCreate_test_fail = false;
    WerReportAddDump_test_fail = true;
    WerReportSubmit_test_fail = false;
    WerReportCreate_test_called = false;
    WerReportAddDump_test_called = false;
    WerReportSubmit_test_called = false;

    // Fail WerReportAddDump
    REQUIRE(AddVectoredExceptionHandler_test_handler(&exception_pointers) == EXCEPTION_CONTINUE_SEARCH);
    REQUIRE(WerReportCreate_test_called);
    REQUIRE(WerReportAddDump_test_called);
    REQUIRE(!WerReportSubmit_test_called);

    WerReportCreate_test_fail = false;
    WerReportAddDump_test_fail = false;
    WerReportSubmit_test_fail = true;
    WerReportCreate_test_called = false;
    WerReportAddDump_test_called = false;
    WerReportSubmit_test_called = false;

    // Fail WerReportSubmit
    REQUIRE(AddVectoredExceptionHandler_test_handler(&exception_pointers) == EXCEPTION_CONTINUE_SEARCH);
    REQUIRE(WerReportCreate_test_called);
    REQUIRE(WerReportAddDump_test_called);
    REQUIRE(WerReportSubmit_test_called);
}

TEST_CASE("watchdog_timeout", "[wer_report]")
{
    WerReportCreate_test_fail = false;
    WerReportAddDump_test_fail = false;
    WerReportSubmit_test_fail = false;
    WerReportCreate_test_called = false;
    WerReportAddDump_test_called = false;
    WerReportSubmit_test_called = false;

    WerReportCreate_test_expected_event_type = L"Test Application Hang";
    WerReportCreate_test_expected_report_type = WerReportApplicationHang;
    WerReportAddDump_test_expected_exception_param = false;

    // Expire the watchdog timer.
    _ebpf_watchdog_timer<false> watchdog_timer(1);
    Sleep(1000);

    // Verify that the WER APIs are all called.
    REQUIRE(WerReportCreate_test_called);
    REQUIRE(WerReportAddDump_test_called);
    REQUIRE(WerReportSubmit_test_called);
}