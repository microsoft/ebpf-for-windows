// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Common test functions used by end to end and component tests.

#include <map>
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "platform.h"
#include "sample_test_common.h"

void
ebpf_test_pinned_map_enum()
{
    int error;
    uint32_t return_value;
    ebpf_result_t result;
    const int pinned_map_count = 10;
    std::string pin_path_prefix = "\\ebpf\\map\\";
    uint16_t map_count = 0;
    ebpf_map_info_t* map_info = nullptr;
    std::map<std::string, std::string> results;

    fd_t map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint64_t), 1024, 0);
    REQUIRE(map_fd >= 0);

    if (map_fd < 0)
        goto Exit;

    for (int i = 0; i < pinned_map_count; i++) {
        std::string pin_path = pin_path_prefix + std::to_string(i);
        error = bpf_obj_pin(map_fd, pin_path.c_str());
        REQUIRE(error == 0);
        if (error != 0)
            goto Exit;
    }

    REQUIRE((result = ebpf_api_get_pinned_map_info(&map_count, &map_info)) == EBPF_SUCCESS);
    if (result != EBPF_SUCCESS)
        goto Exit;

    REQUIRE(map_count == pinned_map_count);
    REQUIRE(map_info != nullptr);
    if (map_info == nullptr)
        goto Exit;

    _Analysis_assume_(pinned_map_count == map_count);
    for (int i = 0; i < pinned_map_count; i++) {
        bool matched = false;
        std::string pin_path = pin_path_prefix + std::to_string(i);
        REQUIRE((
            matched =
                (static_cast<uint16_t>(pin_path.size()) == strnlen_s(map_info[i].pin_path, EBPF_MAX_PIN_PATH_LENGTH))));
        std::string temp(map_info[i].pin_path);
        results[pin_path] = temp;

        // Unpin the object.
        REQUIRE((return_value = ebpf_object_unpin(pin_path.c_str())) == EBPF_SUCCESS);
    }

    REQUIRE(results.size() == pinned_map_count);
    for (int i = 0; i < pinned_map_count; i++) {
        std::string pin_path = pin_path_prefix + std::to_string(i);
        REQUIRE(results.find(pin_path) != results.end());
    }

Exit:
    Platform::_close(map_fd);
    ebpf_api_map_info_free(map_count, map_info);
    map_count = 0;
    map_info = nullptr;
}

void
verify_utility_helper_results(_In_ const bpf_object* object)
{
    fd_t utility_map_fd = bpf_object__find_map_fd_by_name(object, "utility_map");
    ebpf_utility_helpers_data_t test_data[UTILITY_MAP_SIZE];
    for (uint32_t key = 0; key < UTILITY_MAP_SIZE; key++)
        REQUIRE(bpf_map_lookup_elem(utility_map_fd, &key, (void*)&test_data[key]) == EBPF_SUCCESS);

    REQUIRE(test_data[0].random != test_data[1].random);
    REQUIRE(test_data[0].timestamp < test_data[1].timestamp);
    REQUIRE(test_data[0].boot_timestamp < test_data[1].boot_timestamp);
    REQUIRE(
        (test_data[1].boot_timestamp - test_data[0].boot_timestamp) >=
        (test_data[1].timestamp - test_data[0].timestamp));
}
