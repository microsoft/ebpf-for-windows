// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <map>

#define CATCH_CONFIG_MAIN
#include "catch_wrapper.hpp"
#include "netebpf_ext_helper.h"

TEST_CASE("start_stop_test", "[netebpfext]")
{
    netebpf_ext_helper_t helper;

    // Get list of program info providers (attach points and helper functions.
    std::vector<GUID> guids = helper.program_info_provider_guids();
    REQUIRE(guids.size() > 0);
    for (const auto& guid : guids) {
        helper.get_program_info_provider_data(guid);
    }
}
