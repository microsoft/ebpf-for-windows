// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "catch_wrapper.hpp"
#include "ebpf_watchdog_timer.h"

#include <windows.h>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

/**
 * @brief A catch2 listener that triggers a memory dump if the test takes too long.
 */
class _watchdog : public Catch::EventListenerBase
{
  public:
    using Catch::EventListenerBase::EventListenerBase;

    void
    testCaseStarting(Catch::TestCaseInfo const& /*testCaseInfo*/) override
    {
        _watchdog_timer = std::make_unique<_ebpf_watchdog_timer<true>>();
    }

    // Log failed tests.
    void
    testCaseEnded(Catch::TestCaseStats const& /*testCaseInfo*/) override
    {
        _watchdog_timer.reset();
    }

  private:
    std::unique_ptr<_ebpf_watchdog_timer<true>> _watchdog_timer;
};
