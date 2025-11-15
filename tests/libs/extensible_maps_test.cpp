// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Unit test for extensible maps functionality
 */

#include "ebpf_extensible_maps.h"
#include "ebpf_maps.h"
#include "sample_ext_program_info.h"

#include <catch2/catch_all.hpp>

// Test BPF_MAP_TYPE_SAMPLE_MAP which should be handled by extensible maps
#define BPF_MAP_TYPE_SAMPLE_MAP 0xF000

TEST_CASE("extensible_maps_type_check", "[extensible_maps]")
{
    // Test that extensible map types are correctly identified
    REQUIRE(ebpf_map_type_is_extensible(BPF_MAP_TYPE_SAMPLE_MAP));
    REQUIRE(ebpf_map_type_is_extensible(4096));
    REQUIRE(ebpf_map_type_is_extensible(65535));

    // Test that standard map types are not extensible
    REQUIRE_FALSE(ebpf_map_type_is_extensible(BPF_MAP_TYPE_HASH));
    REQUIRE_FALSE(ebpf_map_type_is_extensible(BPF_MAP_TYPE_ARRAY));
    REQUIRE_FALSE(ebpf_map_type_is_extensible(0));
    REQUIRE_FALSE(ebpf_map_type_is_extensible(4095));
}

TEST_CASE("extensible_maps_initialization", "[extensible_maps]")
{
    SECTION("Initialize and cleanup")
    {
        ebpf_result_t result = ebpf_extensible_maps_initiate();
        REQUIRE(result == EBPF_SUCCESS);

        ebpf_extensible_maps_terminate();
    }
}

TEST_CASE("extensible_maps_create_without_provider", "[extensible_maps]")
{
    SECTION("Create extensible map without registered provider")
    {
        ebpf_result_t result = ebpf_extensible_maps_initiate();
        REQUIRE(result == EBPF_SUCCESS);

        ebpf_map_definition_in_memory_t map_def = {
            .type = BPF_MAP_TYPE_SAMPLE_MAP,
            .key_size = sizeof(uint32_t),
            .value_size = sizeof(uint64_t),
            .max_entries = 1024};

        ebpf_map_t* map = nullptr;
        result = ebpf_extensible_map_create(&map_def, ebpf_handle_invalid, &map);

        // Should fail when no provider is registered
        REQUIRE(result == EBPF_EXTENSION_FAILED_TO_LOAD);
        REQUIRE(map == nullptr);

        ebpf_extensible_maps_terminate();
    }
}