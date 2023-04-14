// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

// Winsock2 must be included before windows.h.
#include <winsock2.h>
#include <Windows.h>
#include <errorrep.h>
#include <stdexcept>
#include <stdint.h>
#include <stdlib.h>
#include <werapi.h>

#pragma comment(lib, "wer.lib")

#define FILETIME_TICKS_PER_SECOND 10000000LL        // 100 nanoseconds per tick
#define EBPF_WATCHDOG_TIMER_DUE_TIME_IN_SECONDS 900 // 15 minutes

/**
 * @brief A watchdog timer that triggers a memory dump if the test takes too long.
 *
 * @tparam raise_fast_fail_on_timeout If true, the test will be terminated with a fast fail.
 */
template <bool raise_fast_fail_on_timeout> class _ebpf_watchdog_timer
{
  public:
    _ebpf_watchdog_timer(int64_t timeout = EBPF_WATCHDOG_TIMER_DUE_TIME_IN_SECONDS * FILETIME_TICKS_PER_SECOND)
    {
        timer = CreateThreadpoolTimer(
            [](_Inout_ PTP_CALLBACK_INSTANCE, _Inout_opt_ PVOID, _Inout_ PTP_TIMER) {
                generate_wer_report();
                if constexpr (raise_fast_fail_on_timeout) {
                    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
                }
            },
            NULL,
            NULL);
        if (timer == NULL) {
            throw std::runtime_error("CreateThreadpoolTimer failed");
        }
        int64_t due_time = -timeout;
        SetThreadpoolTimer(timer, reinterpret_cast<FILETIME*>(&due_time), 0, 0);
    }

    ~_ebpf_watchdog_timer()
    {
        if (timer != NULL) {
            SetThreadpoolTimer(timer, NULL, 0, 0);
            WaitForThreadpoolTimerCallbacks(timer, FALSE);
            CloseThreadpoolTimer(timer);
            timer = NULL;
        }
    }

  private:
    static bool
    generate_wer_report()
    {
        HREPORT report_handle;
        HRESULT hr;
        hr = WerReportCreate(wer_event_type, WerReportApplicationHang, nullptr, &report_handle);
        if (FAILED(hr)) {
            return false;
        }
        hr = WerReportAddDump(
            report_handle, GetCurrentProcess(), GetCurrentThread(), WerDumpTypeHeapDump, nullptr, nullptr, 0);
        if (FAILED(hr)) {
            return false;
        }
        hr = WerReportSubmit(report_handle, WerConsentApproved, 0, nullptr);
        if (FAILED(hr)) {
            return false;
        }
        return true;
    }
    static constexpr const wchar_t wer_event_type[] = L"Test Application Hang";
    PTP_TIMER timer;
};

typedef _ebpf_watchdog_timer<true> ebpf_watchdog_timer_t;