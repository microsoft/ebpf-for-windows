// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

// Winsock2 must be included before windows.h.
#include <winsock2.h>
#include <windows.h>

#define FILETIME_TICKS_PER_SECOND 10000000LL        // 100 nanoseconds per tick
#define EBPF_WATCHDOG_TIMER_DUE_TIME_IN_SECONDS 900 // 15 minutes

/**
 * @brief A watchdog timer that triggers a memory dump if the test takes too long.
 */
typedef class _ebpf_watchdog_timer
{
  public:
    _ebpf_watchdog_timer(int64_t timeout = EBPF_WATCHDOG_TIMER_DUE_TIME_IN_SECONDS * FILETIME_TICKS_PER_SECOND)
    {
        timer = CreateThreadpoolTimer(
            [](_Inout_ PTP_CALLBACK_INSTANCE, _Inout_opt_ PVOID, _Inout_ PTP_TIMER) {
                RaiseException(STATUS_ASSERTION_FAILURE, 0, 0, NULL);
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
    PTP_TIMER timer;
} ebpf_watchdog_timer_t;
