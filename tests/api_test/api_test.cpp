// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <mutex>
#include <thread>
#include <WinSock2.h>

#include "api_test.h"
#include "catch2\catch.hpp"
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
    ebpf_handle_t map_handle;
    uint32_t result = 0;
    const int pinned_map_count = 10;
    std::string pin_path_prefix = "\\ebpf\\map\\";
    uint16_t map_count = 0;
    ebpf_map_information_t* map_info = nullptr;

    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);

    REQUIRE(
        (result = ebpf_api_create_map(EBPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint64_t), 1024, &map_handle)) ==
        EBPF_SUCCESS);

    if (result != ERROR_SUCCESS)
        goto Exit;

    for (int i = 0; i < pinned_map_count; i++) {
        std::string pin_path = pin_path_prefix + std::to_string(i);
        REQUIRE(
            (result = ebpf_api_pin_object(
                 map_handle,
                 reinterpret_cast<const uint8_t*>(pin_path.c_str()),
                 static_cast<uint32_t>(pin_path.size()))) == EBPF_SUCCESS);
        if (result != ERROR_SUCCESS)
            goto Exit;
    }

    REQUIRE((result = ebpf_api_get_pinned_map_info(&map_count, &map_info)) == EBPF_SUCCESS);
    if (result != ERROR_SUCCESS)
        goto Exit;

    REQUIRE(map_count == pinned_map_count);

    for (int i = 0; i < pinned_map_count; i++) {
        printf("%s\n", map_info[i].pin_path);

        bool matched = false;
        std::string pin_path = pin_path_prefix + std::to_string(i);
        REQUIRE((
            matched =
                (static_cast<uint16_t>(pin_path.size()) == strnlen_s(map_info[i].pin_path, EBPF_MAX_PIN_PATH_LENGTH))));
        std::string temp(map_info[i].pin_path);
        REQUIRE((matched = (temp == pin_path)));

        if (!matched)
            goto Exit;

        // Unpin the object.
        REQUIRE(
            (result = ebpf_api_unpin_object(
                 reinterpret_cast<const uint8_t*>(pin_path.c_str()), static_cast<uint16_t>(pin_path.size()))) ==
            ERROR_SUCCESS);
    }

Exit:
    ebpf_api_close_handle(map_handle);
    ebpf_api_map_info_free(map_count, map_info);
    map_count = 0;
    map_info = nullptr;

    ebpf_api_terminate();
}