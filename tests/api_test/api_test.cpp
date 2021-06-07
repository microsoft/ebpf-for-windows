// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <mutex>
#include <thread>

#include "api_test.h"
#include "catch2\catch.hpp"
#include "common_tests.h"
#include "service_helper.h"

namespace api_test {
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#include "../sample/ebpf.h"
#pragma warning(pop)
}; // namespace api_test

#define SAMPLE_PATH ""

#define EBPF_CORE_DRIVER_BINARY_NAME L"ebpfcore.sys"
#define EBPF_CORE_DRIVER_NAME L"ebpfcore"

static service_install_helper
    _ebpf_core_driver_helper(EBPF_CORE_DRIVER_NAME, EBPF_CORE_DRIVER_BINARY_NAME, SERVICE_KERNEL_DRIVER);

TEST_CASE("pinned_map_enum", "[pinned_map_enum]")
{
    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);

    ebpf_test_pinned_map_enum();
    ebpf_api_terminate();
}