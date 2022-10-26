// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <windows.h>

#include <fstream>
#include <iostream>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>
#include "catch_wrapper.hpp"

/**
 * @brief A Catch2 reporter that logs the name of each test that passes.
 */
class _passed_test_log : public Catch::EventListenerBase
{
  public:
    using Catch::EventListenerBase::EventListenerBase;

    // Log failed tests.
    void
    testCaseEnded(Catch::TestCaseStats const& testCaseStats) override
    {
        if (!passed_tests) {
            char process_name[MAX_PATH];
            GetModuleFileNameA(nullptr, process_name, MAX_PATH);
            std::string log_file = process_name;
            log_file += ".passed.log";
            passed_tests.open(log_file, std::ios::app);
        }
        if (testCaseStats.totals.assertions.failed == 0) {
            passed_tests << testCaseStats.testInfo->name << std::endl;
            passed_tests.flush();
        }
    }

  private:
    static std::ofstream passed_tests;
};

std::ofstream _passed_test_log::passed_tests;
