// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_EXECUTION_CONTEXT_UNIT_TESTS

#include "catch_wrapper.hpp"
#include "ebpf_async.h"
#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_ring_buffer.h"
#include "execution_context_unit_test_jit.h"
#include "helpers.h"
#include "test_helper.hpp"

#include <iomanip>
#include <optional>
#include <set>

extern "C"
{
    // program context descriptor helpers
    // - Defined in ebpf_program.c, declared here for unit testing.
    void
    ebpf_program_set_header_context_descriptor(
        _In_ const ebpf_context_descriptor_t* context_descriptor, _Inout_ void* program_context);
    void
    ebpf_program_get_header_context_descriptor(
        _In_ const void* program_context, _Outptr_ const ebpf_context_descriptor_t** context_descriptor);
}

struct scoped_cpu_affinity
{
    scoped_cpu_affinity(uint32_t i) : old_affinity_mask{}
    {
        affinity_set = ebpf_set_current_thread_cpu_affinity(i, &old_affinity_mask) == EBPF_SUCCESS;
        REQUIRE(affinity_set);
    }
    ~scoped_cpu_affinity()
    {
        if (affinity_set) {
            ebpf_restore_current_thread_cpu_affinity(&old_affinity_mask);
        }
    }
    GROUP_AFFINITY old_affinity_mask;
    bool affinity_set = false;
};

static const uint32_t _test_map_size = 512;

typedef enum _map_behavior_on_max_entries
{
    MAP_BEHAVIOR_FAIL,
    MAP_BEHAVIOR_REPLACE,
    MAP_BEHAVIOR_INSERT,
} map_behavior_on_max_entries_t;

static void
_test_crud_operations(ebpf_map_type_t map_type)
{
    _ebpf_core_initializer core;
    core.initialize();
    bool is_array;
    bool supports_find_and_delete;
    map_behavior_on_max_entries_t behavior_on_max_entries = MAP_BEHAVIOR_FAIL;
    bool run_at_dpc;
    ebpf_result_t error_on_full;
    ebpf_result_t expected_result;
    switch (map_type) {
    case BPF_MAP_TYPE_HASH:
        is_array = false;
        supports_find_and_delete = true;
        behavior_on_max_entries = MAP_BEHAVIOR_INSERT;
        run_at_dpc = false;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    case BPF_MAP_TYPE_ARRAY:
        is_array = true;
        supports_find_and_delete = false;
        run_at_dpc = false;
        error_on_full = EBPF_INVALID_ARGUMENT;
        break;
    case BPF_MAP_TYPE_PERCPU_HASH:
        is_array = false;
        supports_find_and_delete = true;
        behavior_on_max_entries = MAP_BEHAVIOR_INSERT;
        run_at_dpc = true;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        is_array = true;
        supports_find_and_delete = false;
        run_at_dpc = false;
        error_on_full = EBPF_INVALID_ARGUMENT;
        break;
    case BPF_MAP_TYPE_LRU_HASH:
        is_array = false;
        supports_find_and_delete = true;
        behavior_on_max_entries = MAP_BEHAVIOR_REPLACE;
        run_at_dpc = false;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    case BPF_MAP_TYPE_LRU_PERCPU_HASH:
        is_array = false;
        supports_find_and_delete = true;
        behavior_on_max_entries = MAP_BEHAVIOR_REPLACE;
        run_at_dpc = true;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    default:
        ebpf_assert((false, "Unsupported map type"));
        return;
    }
    std::optional<emulate_dpc_t> dpc;
    if (run_at_dpc) {
        dpc = {emulate_dpc_t(1)};
    }

    ebpf_map_definition_in_memory_t map_definition{map_type, sizeof(uint32_t), sizeof(uint64_t), _test_map_size};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    std::vector<uint8_t> value(ebpf_map_get_definition(map.get())->value_size);
    for (uint32_t key = 0; key < _test_map_size; key++) {
        *reinterpret_cast<uint64_t*>(value.data()) = static_cast<uint64_t>(key) * static_cast<uint64_t>(key);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                sizeof(key),
                reinterpret_cast<const uint8_t*>(&key),
                value.size(),
                value.data(),
                EBPF_ANY,
                0) == EBPF_SUCCESS);
    }

    // Test for inserting max_entries + 1.
    uint32_t bad_key = _test_map_size;
    *reinterpret_cast<uint64_t*>(value.data()) = static_cast<uint64_t>(bad_key) * static_cast<uint64_t>(bad_key);
    REQUIRE(
        ebpf_map_update_entry(
            map.get(),
            sizeof(bad_key),
            reinterpret_cast<const uint8_t*>(&bad_key),
            value.size(),
            value.data(),
            EBPF_ANY,
            0) == ((behavior_on_max_entries != MAP_BEHAVIOR_FAIL) ? EBPF_SUCCESS : error_on_full));

    if (behavior_on_max_entries != MAP_BEHAVIOR_REPLACE) {
        expected_result = (behavior_on_max_entries == MAP_BEHAVIOR_INSERT)
                              ? EBPF_SUCCESS
                              : (is_array ? EBPF_INVALID_ARGUMENT : EBPF_KEY_NOT_FOUND);
        REQUIRE(
            ebpf_map_delete_entry(map.get(), sizeof(bad_key), reinterpret_cast<const uint8_t*>(&bad_key), 0) ==
            expected_result);
    }

    // Now the map has `_test_map_size` entries.

    for (uint32_t key = 0; key < _test_map_size; key++) {
        if (behavior_on_max_entries == MAP_BEHAVIOR_REPLACE) {
            // If map behavior is MAP_BEHAVIOR_REPLACE, then 0th entry would have been evicted.
            expected_result = key == 0 ? EBPF_OBJECT_NOT_FOUND : EBPF_SUCCESS;
        } else if (behavior_on_max_entries == MAP_BEHAVIOR_INSERT) {
            expected_result = EBPF_SUCCESS;
        } else {
            expected_result = key == _test_map_size ? EBPF_OBJECT_NOT_FOUND : EBPF_SUCCESS;
        }
        REQUIRE(
            ebpf_map_find_entry(
                map.get(), sizeof(key), reinterpret_cast<const uint8_t*>(&key), value.size(), value.data(), 0) ==
            expected_result);
        if (expected_result == EBPF_SUCCESS) {
            REQUIRE(*reinterpret_cast<uint64_t*>(value.data()) == key * key);
        }
    }

    uint32_t previous_key;
    uint32_t next_key;
    std::set<uint32_t> keys;
    for (uint32_t key = 0; key < _test_map_size; key++) {
        REQUIRE(
            ebpf_map_next_key(
                map.get(),
                sizeof(key),
                key == 0 ? nullptr : reinterpret_cast<const uint8_t*>(&previous_key),
                reinterpret_cast<uint8_t*>(&next_key)) == EBPF_SUCCESS);

        previous_key = next_key;
        keys.insert(previous_key);
    }
    REQUIRE(keys.size() == _test_map_size);

    REQUIRE(
        ebpf_map_next_key(
            map.get(),
            sizeof(previous_key),
            reinterpret_cast<const uint8_t*>(&previous_key),
            reinterpret_cast<uint8_t*>(&next_key)) == EBPF_NO_MORE_KEYS);

    std::vector<size_t> batch_test_sizes = {
        1,
        17,
        _test_map_size / 4,
        _test_map_size,
        _test_map_size * 2,
    };
    for (size_t batch_count : batch_test_sizes) {

        keys.clear();
        size_t effective_key_size = ebpf_map_get_definition(map.get())->key_size;
        size_t effective_value_size = ebpf_map_get_definition(map.get())->value_size;
        std::vector<uint8_t> batch_data(batch_count * (effective_key_size + effective_value_size));
        ebpf_result_t return_value = EBPF_SUCCESS;

        for (uint32_t index = 0; return_value == EBPF_SUCCESS; index++) {
            size_t batch_data_size = batch_data.size();
            return_value = ebpf_map_get_next_key_and_value_batch(
                map.get(),
                sizeof(previous_key),
                index == 0 ? nullptr : reinterpret_cast<uint8_t*>(&previous_key),
                &batch_data_size,
                batch_data.data(),
                0);

            if (return_value == EBPF_NO_MORE_KEYS) {
                break;
            }

            REQUIRE(return_value == EBPF_SUCCESS);

            REQUIRE(batch_data_size <= batch_data.size());
            size_t returned_batch_count = batch_data_size / (effective_key_size + effective_value_size);

            // Verify that all keys are returned.
            for (uint32_t batch_index = 0; batch_index < returned_batch_count; batch_index++) {
                uint32_t current_key = *reinterpret_cast<uint32_t*>(
                    &batch_data[batch_index * (effective_key_size + effective_value_size)]);
                uint64_t current_value = *reinterpret_cast<uint64_t*>(
                    &batch_data[batch_index * (effective_key_size + effective_value_size) + effective_key_size]);
                keys.insert(current_key);
                REQUIRE(current_value == current_key * current_key);
            }
            previous_key = *reinterpret_cast<uint32_t*>(
                &batch_data[(returned_batch_count - 1) * (effective_key_size + effective_value_size)]);
        }
        REQUIRE(keys.size() == _test_map_size);
    }

    for (const auto key : keys) {
        REQUIRE(
            ebpf_map_delete_entry(map.get(), sizeof(key), reinterpret_cast<const uint8_t*>(&key), 0) == EBPF_SUCCESS);
    }

    if (supports_find_and_delete) {
        uint32_t key = 0;
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                sizeof(key),
                reinterpret_cast<const uint8_t*>(&key),
                value.size(),
                value.data(),
                EBPF_ANY,
                0) == EBPF_SUCCESS);

        REQUIRE(
            ebpf_map_find_entry(
                map.get(),
                sizeof(key),
                reinterpret_cast<const uint8_t*>(&key),
                value.size(),
                value.data(),
                EBPF_MAP_FIND_FLAG_DELETE) == EBPF_SUCCESS);

        REQUIRE(
            ebpf_map_find_entry(
                map.get(), sizeof(key), reinterpret_cast<const uint8_t*>(&key), value.size(), value.data(), 0) ==
            EBPF_OBJECT_NOT_FOUND);
    } else {
        uint32_t key = 0;
        REQUIRE(
            ebpf_map_find_entry(
                map.get(),
                sizeof(key),
                reinterpret_cast<const uint8_t*>(&key),
                value.size(),
                value.data(),
                EBPF_MAP_FIND_FLAG_DELETE) == EBPF_INVALID_ARGUMENT);
    }

    auto retrieved_map_definition = *ebpf_map_get_definition(map.get());
    retrieved_map_definition.value_size = ebpf_map_get_effective_value_size(map.get());
    REQUIRE(memcmp(&retrieved_map_definition, &map_definition, sizeof(map_definition)) == 0);

    // Negative test for key size.
    uint32_t key = 0;
    REQUIRE(
        ebpf_map_next_key(
            map.get(), sizeof(key) - 1, reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key)) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(ebpf_map_push_entry(map.get(), value.size(), value.data(), 0) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_map_pop_entry(map.get(), value.size(), value.data(), 0) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_map_peek_entry(map.get(), value.size(), value.data(), 0) == EBPF_INVALID_ARGUMENT);
}

#define MAP_TEST(MAP_TYPE) \
    TEST_CASE("map_crud_operations:" #MAP_TYPE, "[execution_context]") { _test_crud_operations(MAP_TYPE); }

MAP_TEST(BPF_MAP_TYPE_HASH);
MAP_TEST(BPF_MAP_TYPE_ARRAY);
MAP_TEST(BPF_MAP_TYPE_PERCPU_HASH);
MAP_TEST(BPF_MAP_TYPE_PERCPU_ARRAY);
MAP_TEST(BPF_MAP_TYPE_LRU_HASH);
MAP_TEST(BPF_MAP_TYPE_LRU_PERCPU_HASH);

TEST_CASE("map_create_invalid", "[execution_context][negative]")
{
    _ebpf_core_initializer core;
    core.initialize();

    // Define map definitions with invalid parameters.
    std::map<std::string, ebpf_map_definition_in_memory_t> invalid_map_definitions = {
        {
            "BPF_MAP_TYPE_ARRAY",
            {
                BPF_MAP_TYPE_ARRAY,
                4,
                4284506112, // Value size / capacity combination allocates >128GB.
                105512960,
            },
        },
        {
            "BPF_MAP_TYPE_RINGBUF",
            {
                BPF_MAP_TYPE_RINGBUF,
                4, // Key size must be 0 for ring buffer.
                20,
                20,
            },
        },
        {
            "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
            {
                BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                4, // Key size must be 0 for perf event array.
                20,
                20,
            },
        },
        {
            "BPF_MAP_TYPE_HASH_OF_MAPS",
            {
                BPF_MAP_TYPE_HASH_OF_MAPS,
                4,
                0, // Value size must equal sizeof(ebpf_id_t)
                10,
                1,
            },
        },
        {
            "BPF_MAP_TYPE_ARRAY_OF_MAPS",
            {
                BPF_MAP_TYPE_ARRAY_OF_MAPS,
                4,
                0, // Value size must equal sizeof(ebpf_id_t)
                10,
                1,
            },
        },
    };

    for (const auto& [name, def] : invalid_map_definitions) {
        cxplat_utf8_string_t utf8_name{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())), name.size()};
        ebpf_handle_t handle;
        ebpf_handle_t inner_handle = ebpf_handle_invalid;
        CAPTURE(name);
        REQUIRE(ebpf_core_create_map(&utf8_name, &def, inner_handle, &handle) == EBPF_INVALID_ARGUMENT);
    }
}

// Helper struct to represent a 32 bit IP prefix.
typedef struct _lpm_trie_32_key
{
    uint32_t prefix_length;
    uint8_t value[4];
} lpm_trie_32_key_t;

// Helper function to create a string representation of a 32 bit ip prefix.
std::string
_ip32_prefix_string(uint32_t prefix_length, const uint8_t value[])
{
    std::string key_string = std::to_string(value[0]) + "." + std::to_string(value[1]) + "." +
                             std::to_string(value[2]) + "." + std::to_string(value[3]) + "/" +
                             std::to_string(prefix_length);
    return key_string;
}

// Helper function to create a pair of lpm_trie_32_key_t and the string representation of the 32 bit ip prefix.
std::pair<lpm_trie_32_key_t, std::string>
_lpm_ip32_prefix_pair(uint32_t prefix_length, uint8_t byte0, uint8_t byte1, uint8_t byte2, uint8_t byte3)
{
    lpm_trie_32_key_t key{prefix_length, {byte0, byte1, byte2, byte3}};
    return {key, _ip32_prefix_string(prefix_length, key.value)};
}

TEST_CASE("map_crud_operations_lpm_trie_32", "[execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();
    const size_t max_string = 17;

    std::vector<std::pair<lpm_trie_32_key_t, std::string>> keys{
        _lpm_ip32_prefix_pair(24, 192, 168, 15, 0),
        _lpm_ip32_prefix_pair(24, 192, 168, 16, 0),
        _lpm_ip32_prefix_pair(31, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(30, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(29, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(32, 192, 168, 15, 7),
        _lpm_ip32_prefix_pair(16, 192, 168, 0, 0),
        _lpm_ip32_prefix_pair(32, 10, 10, 255, 255),
        _lpm_ip32_prefix_pair(16, 10, 10, 0, 0),
        _lpm_ip32_prefix_pair(8, 10, 0, 0, 0),
        _lpm_ip32_prefix_pair(0, 0, 0, 0, 0),
    };

    std::vector<std::pair<lpm_trie_32_key_t, std::string>> tests{
        {{32, 192, 168, 15, 1}, "192.168.15.0/24"},
        {{32, 192, 168, 15, 7}, "192.168.15.7/32"},
        {{32, 192, 168, 16, 25}, "192.168.16.0/24"},
        {{32, 192, 168, 14, 1}, "192.168.14.0/31"},
        {{32, 192, 168, 14, 2}, "192.168.14.0/30"},
        {{32, 192, 168, 14, 4}, "192.168.14.0/29"},
        {{32, 192, 168, 14, 9}, "192.168.0.0/16"},
        {{32, 10, 10, 255, 255}, "10.10.255.255/32"},
        {{32, 10, 10, 10, 10}, "10.10.0.0/16"},
        {{32, 10, 11, 10, 10}, "10.0.0.0/8"},
        {{8, 10, 10, 10, 10}, "10.0.0.0/8"},
        {{32, 11, 0, 0, 0}, "0.0.0.0/0"},
    };

    uint32_t max_entries = static_cast<uint32_t>(keys.size());
    ebpf_map_definition_in_memory_t map_definition{
        BPF_MAP_TYPE_LPM_TRIE, sizeof(lpm_trie_32_key_t), max_string, max_entries};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    // Insert keys into the map.
    for (auto [key, key_string] : keys) {
        key_string.resize(max_string);
        CAPTURE(key_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(key_string.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    // Make sure we can find all the keys we just inserted.
    for (const auto& [key, correct_value] : keys) {
        std::string key_string = _ip32_prefix_string(key.prefix_length, key.value);
        CAPTURE(key_string, correct_value);
        char* return_value = nullptr;
        CHECK(
            ebpf_map_find_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<uint8_t*>(&return_value),
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
        CHECK(return_value == correct_value);
    }

    // Lookup IP prefixes in the map.
    for (const auto& [key, correct_value] : tests) {
        std::string key_string = _ip32_prefix_string(key.prefix_length, key.value);
        CAPTURE(key_string, correct_value);
        char* return_value = nullptr;
        CHECK(
            ebpf_map_find_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<uint8_t*>(&return_value),
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
        CHECK(return_value == correct_value);
    }

    {
        // Insert a new key.
        lpm_trie_32_key_t key = {32, 192, 168, 15, 1};
        std::string key_string = _ip32_prefix_string(key.prefix_length, key.value);
        CAPTURE(key_string);
        key_string.resize(max_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(key_string.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    // Re-insert the same keys (to test update)
    for (auto [key, key_string] : keys) {
        key_string.resize(max_string);
        CAPTURE(key_string);
        CHECK(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(key_string.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    // Delete all the keys.
    for (const auto& [key, key_string] : keys) {
        CAPTURE(key_string);
        CHECK(
            ebpf_map_delete_entry(map.get(), 0, reinterpret_cast<const uint8_t*>(&key), EBPF_MAP_FLAG_HELPER) ==
            EBPF_SUCCESS);
    }
}

TEST_CASE("map_crud_operations_lpm_trie_32", "[execution_context][negative]")
{
    _ebpf_core_initializer core;
    core.initialize();
    const size_t max_string = 21;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_LPM_TRIE, sizeof(lpm_trie_32_key_t), max_string, 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    std::vector<std::pair<lpm_trie_32_key_t, std::string>> invalid_keys{
        _lpm_ip32_prefix_pair((uint32_t)-1, 192, 168, 0, 1),
        _lpm_ip32_prefix_pair(33, 10, 0, 0, 1),
        _lpm_ip32_prefix_pair(100, 172, 16, 0, 1),
    };

    std::vector<std::pair<lpm_trie_32_key_t, std::string>> keys{
        _lpm_ip32_prefix_pair(24, 192, 168, 15, 0),
        _lpm_ip32_prefix_pair(24, 192, 168, 16, 0),
        _lpm_ip32_prefix_pair(31, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(30, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(29, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(16, 192, 168, 0, 0),
        _lpm_ip32_prefix_pair(12, 172, 16, 0, 0),
        _lpm_ip32_prefix_pair(8, 10, 0, 0, 0),
    };

    std::vector<std::pair<lpm_trie_32_key_t, std::string>> negative_tests{
        _lpm_ip32_prefix_pair(32, 192, 169, 0, 0),
        _lpm_ip32_prefix_pair(24, 192, 169, 0, 0),
        _lpm_ip32_prefix_pair(15, 192, 168, 0, 0),
        _lpm_ip32_prefix_pair(0, 192, 168, 0, 0),
        _lpm_ip32_prefix_pair(12, 172, 48, 0, 0),
        _lpm_ip32_prefix_pair(11, 172, 16, 0, 0),
        _lpm_ip32_prefix_pair(8, 11, 0, 0, 0),
        _lpm_ip32_prefix_pair(8, 11, 0, 0, 0),
        _lpm_ip32_prefix_pair(0, 0, 0, 0, 0),
    };

    // Inserting invalid keys should return EBPF_INVALID_ARGUMENT.
    for (auto [key, key_string] : invalid_keys) {
        CAPTURE(key_string);
        key_string.resize(max_string);
        ebpf_result_t status = ebpf_map_update_entry(
            map.get(),
            0,
            reinterpret_cast<const uint8_t*>(&key),
            0,
            reinterpret_cast<const uint8_t*>(key_string.c_str()),
            EBPF_ANY,
            EBPF_MAP_FLAG_HELPER);
        REQUIRE(status == EBPF_INVALID_ARGUMENT);
    }

    // Looking up invalid keys should return EBPF_INVALID_ARGUMENT
    for (const auto& [key, key_string] : invalid_keys) {
        CAPTURE(key_string);
        char* return_value = nullptr;
        ebpf_result_t status = ebpf_map_find_entry(
            map.get(),
            0,
            reinterpret_cast<const uint8_t*>(&key),
            0,
            reinterpret_cast<uint8_t*>(&return_value),
            EBPF_MAP_FLAG_HELPER);
        REQUIRE(status == EBPF_INVALID_ARGUMENT);
        REQUIRE(return_value == nullptr);
    }

    // Deleting invalid keys should return EBPF_INVALID_ARGUMENT
    for (const auto& [key, key_string] : invalid_keys) {
        CAPTURE(key_string);
        ebpf_result_t status =
            ebpf_map_delete_entry(map.get(), 0, reinterpret_cast<const uint8_t*>(&key), EBPF_MAP_FLAG_HELPER);
        REQUIRE(status == EBPF_INVALID_ARGUMENT);
    }

    // Now insert some valid keys for testing.
    for (auto [key, key_string] : keys) {
        CAPTURE(key_string);
        key_string.resize(max_string);
        ebpf_result_t status = ebpf_map_update_entry(
            map.get(),
            0,
            reinterpret_cast<const uint8_t*>(&key),
            0,
            reinterpret_cast<const uint8_t*>(key_string.c_str()),
            EBPF_ANY,
            EBPF_MAP_FLAG_HELPER);
        REQUIRE(status == EBPF_SUCCESS);
    }

    // Sanity check by looking up the valid keys.
    for (const auto& [key, key_string] : keys) {
        CAPTURE(key_string);
        char* return_value = nullptr;
        ebpf_result_t status = ebpf_map_find_entry(
            map.get(),
            0,
            reinterpret_cast<const uint8_t*>(&key),
            0,
            reinterpret_cast<uint8_t*>(&return_value),
            EBPF_MAP_FLAG_HELPER);
        CAPTURE(return_value);
        REQUIRE(status == EBPF_SUCCESS);
        REQUIRE(return_value != nullptr);
        REQUIRE(return_value == key_string);
    }

    // Keys that don't exist should return EBPF_KEY_NOT_FOUND.
    for (const auto& [key, key_string] : negative_tests) {
        CAPTURE(key_string);
        char* return_value = nullptr;
        ebpf_result_t status = ebpf_map_find_entry(
            map.get(),
            0,
            reinterpret_cast<const uint8_t*>(&key),
            0,
            reinterpret_cast<uint8_t*>(&return_value),
            EBPF_MAP_FLAG_HELPER);
        CAPTURE(return_value);
        CHECK(status == EBPF_KEY_NOT_FOUND);
        CHECK(return_value == nullptr);
    }

    // Deleting keys that don't exist should return EBPF_KEY_NOT_FOUND.
    for (const auto& [key, key_string] : negative_tests) {
        CAPTURE(key_string);

#pragma warning(push)
#pragma warning(disable : 28193)
        // Analyze build throws 28193 for unexamined return value (status)
        ebpf_result_t status =
            ebpf_map_delete_entry(map.get(), 0, reinterpret_cast<const uint8_t*>(&key), EBPF_MAP_FLAG_HELPER);
#pragma warning(pop)
        REQUIRE(status == EBPF_KEY_NOT_FOUND);
    }
}

// Helper struct to represent a 128 bit prefix.
typedef struct _lpm_trie_128_key
{
    uint32_t prefix_length;
    uint8_t value[16];
} lpm_trie_128_key_t;

std::string
_lpm_128_simple_prefix_string(uint32_t prefix_length, uint8_t value)
{
    std::stringstream builder;
    builder << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << (int)value << "/"
            << std::to_string(prefix_length);
    return builder.str();
}

// Helper function to create a pair of lpm_trie_128_key_t and the string representation.
// - Generates the prefix by duplicating the given value.
// - if prefix_string is empty, it is filled with "XX/N" where XX is value in hex, and N is prefix_length.
std::pair<lpm_trie_128_key_t, std::string>
_lpm_128_prefix_pair(uint32_t prefix_length, uint8_t value, std::string prefix_string = "")
{
    lpm_trie_128_key_t key{prefix_length};
    memset(key.value, value, (prefix_length + 7) / 8);

    if (prefix_string.empty()) {
        prefix_string = _lpm_128_simple_prefix_string(prefix_length, value);
    }

    return {key, prefix_string};
}

TEST_CASE("map_crud_operations_lpm_trie_128", "[execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();

    const size_t max_string = 20;
    std::vector<std::pair<lpm_trie_128_key_t, std::string>> keys{
        _lpm_128_prefix_pair(96, 0xCC),
        _lpm_128_prefix_pair(96, 0xCD),
        _lpm_128_prefix_pair(124, 0xDD),
        _lpm_128_prefix_pair(120, 0xDD),
        _lpm_128_prefix_pair(116, 0xDD),
        _lpm_128_prefix_pair(64, 0xAA),
        _lpm_128_prefix_pair(128, 0xBB),
        _lpm_128_prefix_pair(127, 0xBB),
        _lpm_128_prefix_pair(64, 0xBB),
        _lpm_128_prefix_pair(32, 0xBB),
        _lpm_128_prefix_pair(0, 0),
    };

    uint32_t max_entries = static_cast<uint32_t>(keys.size());
    ebpf_map_definition_in_memory_t map_definition{
        BPF_MAP_TYPE_LPM_TRIE, sizeof(lpm_trie_128_key_t), max_string, max_entries};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    std::vector<std::pair<lpm_trie_128_key_t, std::string>> tests{
        _lpm_128_prefix_pair(97, 0xCC, "CC/96"),
        _lpm_128_prefix_pair(120, 0xCD, "CD/96"),
        _lpm_128_prefix_pair(125, 0xDD, "DD/124"),
        _lpm_128_prefix_pair(124, 0xDD),
        _lpm_128_prefix_pair(123, 0xDD, "DD/120"),
        _lpm_128_prefix_pair(121, 0xDD, "DD/120"),
        _lpm_128_prefix_pair(120, 0xDD),
        _lpm_128_prefix_pair(119, 0xDD, "DD/116"),
        _lpm_128_prefix_pair(116, 0xDD),
        _lpm_128_prefix_pair(115, 0xDD, "00/0"),
        _lpm_128_prefix_pair(72, 0xAA, "AA/64"),
        _lpm_128_prefix_pair(128, 0xBB),
        _lpm_128_prefix_pair(127, 0xBB),
        _lpm_128_prefix_pair(126, 0xBB, "BB/64"),
        _lpm_128_prefix_pair(65, 0xBB, "BB/64"),
        _lpm_128_prefix_pair(64, 0xBB),
        _lpm_128_prefix_pair(63, 0xBB, "BB/32"),
        _lpm_128_prefix_pair(33, 0xBB, "BB/32"),
        _lpm_128_prefix_pair(32, 0xBB),
        _lpm_128_prefix_pair(31, 0xBB, "00/0"),
        _lpm_128_prefix_pair(128, 0xFF, "00/0"),
    };

    // Insert keys into the map.
    for (auto& [key, value] : keys) {
        std::string key_string = value;
        CAPTURE(key_string);
        key_string.resize(max_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(key_string.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    // Verify looking up the keys we inserted returns the same value
    for (auto& [key, key_string] : keys) {
        CAPTURE(key_string);
        char* return_value = nullptr;
        CHECK(
            ebpf_map_find_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<uint8_t*>(&return_value),
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
        CHECK(std::string(return_value) == key_string);
    }

    // Perform additional lookup tests
    for (auto& [key, correct_value] : tests) {
        std::string key_string = _lpm_128_simple_prefix_string(key.prefix_length, key.value[0]);
        CAPTURE(key_string, correct_value);
        char* return_value = nullptr;
        CHECK(
            ebpf_map_find_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<uint8_t*>(&return_value),
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
        CHECK(std::string(return_value) == correct_value);
    }

    {
        // Update an existing entry, it should succeed.
        auto lpm_pair = _lpm_128_prefix_pair(32, 0xBB);
        std::string key_string = lpm_pair.second;
        CAPTURE(key_string);
        lpm_pair.second.resize(max_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&lpm_pair.first),
                0,
                reinterpret_cast<const uint8_t*>(lpm_pair.second.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }
    {
        // Add a new entry to the map, it should succeed.
        auto lpm_pair = _lpm_128_prefix_pair(33, 0xBB);
        std::string key_string = lpm_pair.second;
        CAPTURE(key_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&lpm_pair.first),
                0,
                reinterpret_cast<const uint8_t*>(lpm_pair.second.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    // Delete all the keys we originally inserted.
    for (const auto& [key, key_string] : keys) {
        CAPTURE(key_string);
        CHECK(
            ebpf_map_delete_entry(map.get(), 0, reinterpret_cast<const uint8_t*>(&key), EBPF_MAP_FLAG_HELPER) ==
            EBPF_SUCCESS);
    }
}

TEST_CASE("map_crud_operations_queue", "[execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_QUEUE, 0, sizeof(uint32_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    uint32_t return_value = MAXUINT32;

    // Should be empty.
    REQUIRE(
        ebpf_map_pop_entry(map.get(), sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_OBJECT_NOT_FOUND);

    for (uint32_t value = 0; value < 10; value++) {
        REQUIRE(ebpf_map_push_entry(map.get(), sizeof(value), reinterpret_cast<uint8_t*>(&value), 0) == EBPF_SUCCESS);
    }
    uint32_t extra_value = 10;
    REQUIRE(
        ebpf_map_push_entry(map.get(), sizeof(extra_value), reinterpret_cast<uint8_t*>(&extra_value), 0) ==
        EBPF_OUT_OF_SPACE);

    // Replace the oldest entry.
    REQUIRE(
        ebpf_map_push_entry(map.get(), sizeof(extra_value), reinterpret_cast<uint8_t*>(&extra_value), BPF_EXIST) ==
        EBPF_SUCCESS);

    // Peek at first element.
    REQUIRE(
        ebpf_map_peek_entry(map.get(), sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_SUCCESS);

    REQUIRE(return_value == 1);

    for (uint32_t value = 1; value < 11; value++) {
        REQUIRE(
            ebpf_map_pop_entry(map.get(), sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
            EBPF_SUCCESS);
        REQUIRE(return_value == value);
    }

    REQUIRE(
        ebpf_map_pop_entry(map.get(), sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_OBJECT_NOT_FOUND);

    // Negative tests.
    REQUIRE(
        ebpf_map_delete_entry(map.get(), sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(
        ebpf_map_delete_entry(map.get(), sizeof(return_value) - 1, reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(
        ebpf_map_pop_entry(map.get(), sizeof(return_value) - 1, reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(
        ebpf_map_push_entry(map.get(), sizeof(return_value) - 1, reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(
        ebpf_map_peek_entry(map.get(), sizeof(return_value) - 1, reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_INVALID_ARGUMENT);

    // Wrong key size.
    REQUIRE(
        ebpf_map_update_entry_with_handle(
            map.get(), sizeof(return_value) - 1, reinterpret_cast<uint8_t*>(&return_value), 0, EBPF_ANY) ==
        EBPF_INVALID_ARGUMENT);

    // Not supported.
    REQUIRE(
        ebpf_map_update_entry_with_handle(
            map.get(), sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0, EBPF_ANY) ==
        EBPF_INVALID_ARGUMENT);
}

TEST_CASE("map_crud_operations_stack", "[execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_STACK, 0, sizeof(uint32_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    uint32_t return_value = MAXUINT32;

    // Should be empty.
    REQUIRE(
        ebpf_map_pop_entry(map.get(), sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_OBJECT_NOT_FOUND);

    for (uint32_t value = 1; value < 11; value++) {
        REQUIRE(ebpf_map_push_entry(map.get(), sizeof(value), reinterpret_cast<uint8_t*>(&value), 0) == EBPF_SUCCESS);
    }
    uint32_t extra_value = 11;
    REQUIRE(
        ebpf_map_push_entry(map.get(), sizeof(extra_value), reinterpret_cast<uint8_t*>(&extra_value), 0) ==
        EBPF_OUT_OF_SPACE);

    // Replace the oldest entry.
    REQUIRE(
        ebpf_map_push_entry(map.get(), sizeof(extra_value), reinterpret_cast<uint8_t*>(&extra_value), BPF_EXIST) ==
        EBPF_SUCCESS);

    // Peek at first element.
    REQUIRE(
        ebpf_map_peek_entry(map.get(), sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_SUCCESS);

    REQUIRE(return_value == 11);

    for (uint32_t value = 11; value > 1; value--) {
        REQUIRE(
            ebpf_map_pop_entry(map.get(), sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
            EBPF_SUCCESS);
        REQUIRE(return_value == value);
    }

    REQUIRE(
        ebpf_map_peek_entry(map.get(), sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_OBJECT_NOT_FOUND);
}

std::vector<GUID> _program_types = {
    EBPF_PROGRAM_TYPE_XDP,
    EBPF_PROGRAM_TYPE_BIND,
    EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
    EBPF_PROGRAM_TYPE_SOCK_OPS,
    EBPF_PROGRAM_TYPE_SAMPLE};

std::map<std::string, ebpf_map_definition_in_memory_t> _map_definitions = {
    {
        "BPF_MAP_TYPE_ARRAY",
        {
            BPF_MAP_TYPE_ARRAY,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_ARRAY_OF_MAPS",
        {
            BPF_MAP_TYPE_ARRAY_OF_MAPS,
            4,
            4,
            10,
            1,
        },
    },
    {
        "BPF_MAP_TYPE_HASH",
        {
            BPF_MAP_TYPE_HASH,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_HASH_OF_MAPS",
        {
            BPF_MAP_TYPE_HASH_OF_MAPS,
            4,
            4,
            10,
            1,
        },
    },
    {
        "BPF_MAP_TYPE_PERCPU_ARRAY",
        {
            BPF_MAP_TYPE_PERCPU_ARRAY,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_PERCPU_HASH",
        {
            BPF_MAP_TYPE_PERCPU_HASH,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_PROG_ARRAY",
        {
            BPF_MAP_TYPE_PROG_ARRAY,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_LPM_TRIE",
        {
            BPF_MAP_TYPE_LPM_TRIE,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_LRU_HASH",
        {
            BPF_MAP_TYPE_LRU_HASH,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_LRU_PERCPU_HASH",
        {
            BPF_MAP_TYPE_LRU_PERCPU_HASH,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_QUEUE",
        {
            BPF_MAP_TYPE_QUEUE,
            0,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_STACK",
        {
            BPF_MAP_TYPE_STACK,
            0,
            20,
            10,
        },
    },
};

uint32_t
test_function()
{
    return TEST_FUNCTION_RETURN;
}

TEST_CASE("name size", "[execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();
    program_info_provider_t program_info_provider;
    REQUIRE(program_info_provider.initialize(EBPF_PROGRAM_TYPE_BIND) == EBPF_SUCCESS);
    const cxplat_utf8_string_t oversize_name{
        (uint8_t*)("a234567890123456789012345678901234567890123456789012345678901234"), 64};
    const cxplat_utf8_string_t section_name{(uint8_t*)("bar"), 3};
    const ebpf_program_parameters_t program_parameters{
        EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND, oversize_name, section_name};
    ebpf_program_t* local_program = nullptr;
    REQUIRE(ebpf_program_create(&program_parameters, &local_program) == EBPF_INVALID_ARGUMENT);

    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint64_t), 10};
    ebpf_map_t* local_map;
    REQUIRE(
        ebpf_map_create(&oversize_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) ==
        EBPF_INVALID_ARGUMENT);
}

const uint16_t from_buffer[] = {0x4500, 0x0073, 0x0000, 0x4000, 0x4011, 0x0000, 0x2000, 0x0001, 0x2000, 0x000a};
const uint16_t to_buffer[] = {0x4500, 0x0073, 0x0000, 0x4000, 0x4011, 0x0000, 0xc0a8, 0x0001, 0xc0a8, 0x00c7};

TEST_CASE("test-csum-diff", "[execution_context]")
{
    int csum = ebpf_core_csum_diff(
        from_buffer,
        sizeof(from_buffer),
        to_buffer,
        sizeof(to_buffer),
        ebpf_core_csum_diff(nullptr, 0, from_buffer, sizeof(from_buffer), 0));
    REQUIRE(csum > 0);

    // Fold checksum.
    csum = (csum >> 16) + (csum & 0xFFFF);
    csum = (csum >> 16) + (csum & 0xFFFF);
    csum = (uint16_t)~csum;

    // See: https://en.wikipedia.org/wiki/IPv4_header_checksum#Calculating_the_IPv4_header_checksum
    REQUIRE(csum == 0xb861);
}

TEST_CASE("ring_buffer_async_query", "[execution_context][ring_buffer]")
{
    _ebpf_core_initializer core;
    core.initialize();
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_RINGBUF, 0, 0, 64 * 1024};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    struct _completion
    {
        uint8_t* buffer = nullptr;
        uint32_t buffer_size = 64 * 1024;
        size_t consumer_offset = 0;
        ebpf_map_async_query_result_t async_query_result = {};
        volatile uint64_t value{};
    } completion;

    REQUIRE(ebpf_map_query_buffer(map.get(), 0, &completion.buffer, &completion.consumer_offset) == EBPF_SUCCESS);
    // Initialize consumer offset in async result used to track current position.
    completion.async_query_result.consumer = completion.consumer_offset;

    REQUIRE(
        ebpf_async_set_completion_callback(
            &completion, [](_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result) {
                UNREFERENCED_PARAMETER(output_buffer_length);
                auto completion = reinterpret_cast<_completion*>(context);
                auto async_query_result = &completion->async_query_result;
                auto record = ebpf_ring_buffer_next_record(
                    completion->buffer,
                    completion->buffer_size,
                    async_query_result->consumer,
                    async_query_result->producer);
                if (!ebpf_ring_buffer_record_is_locked(record)) {
                    completion->value = *(uint64_t*)(record->data);
                }
                REQUIRE(result == EBPF_SUCCESS);
            }) == EBPF_SUCCESS);

    ebpf_result_t result = ebpf_map_async_query(map.get(), 0, &completion.async_query_result, &completion);
    if (result != EBPF_PENDING) {
        REQUIRE(ebpf_async_reset_completion_callback(&completion) == EBPF_SUCCESS);
    }
    REQUIRE(result == EBPF_PENDING);

    uint64_t value = 1;
    REQUIRE(ebpf_ring_buffer_map_output(map.get(), reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);

    REQUIRE(completion.value == value);
}

TEST_CASE("ring_buffer_sync_query", "[execution_context][ring_buffer]")
{
    _ebpf_core_initializer core;
    core.initialize();
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_RINGBUF, 0, 0, 64 * 1024};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    _wait_event event;
    REQUIRE(ebpf_map_set_wait_handle_internal(map.get(), 0, event.handle(), 0) == EBPF_SUCCESS);

    // Output a value to the ring buffer.
    uint64_t value = 42;
    REQUIRE(ebpf_ring_buffer_map_output(map.get(), reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);

    // Map the ring buffer to get consumer and producer pointers.
    volatile size_t* consumer = nullptr;
    volatile size_t* producer = nullptr;
    uint8_t* data = nullptr;
    size_t data_size = 0;
    REQUIRE(
        ebpf_ring_buffer_map_map_user(
            map.get(), (void**)&consumer, (void**)&producer, (const uint8_t**)&data, &data_size) == EBPF_SUCCESS);

    // Use the mapped producer pointer to read the record.
    auto record = ebpf_ring_buffer_next_record(data, 64 * 1024, *consumer, *producer);

    REQUIRE(record != nullptr);
    REQUIRE(!ebpf_ring_buffer_record_is_locked(record));
    REQUIRE(!ebpf_ring_buffer_record_is_discarded(record));
    REQUIRE(ebpf_ring_buffer_record_length(record) == sizeof(value));
    REQUIRE(*(uint64_t*)(record->data) == value);

    // Unmap the ring buffer.
    REQUIRE(
        ebpf_ring_buffer_map_unmap_user(map.get(), (const void*)consumer, (const void*)producer, (const void*)data) ==
        EBPF_SUCCESS);
}

TEST_CASE("perf_event_array_unsupported_ops", "[execution_context][perf_event_array][negative]")
{
    _ebpf_core_initializer core;
    core.initialize();
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_PERF_EVENT_ARRAY, 0, 0, 64 * 1024};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    uint32_t key = 0;
    uint32_t value2 = 0;
    REQUIRE(
        ebpf_map_update_entry(map.get(), sizeof(key), reinterpret_cast<uint8_t*>(&key), 0, nullptr, EBPF_ANY, 0) ==
        EBPF_INVALID_ARGUMENT);

    // Negative test cases.
    REQUIRE(
        ebpf_map_update_entry(
            map.get(), 0, nullptr, sizeof(value2), reinterpret_cast<uint8_t*>(&value2), EBPF_ANY, 0) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(ebpf_map_update_entry(map.get(), 0, nullptr, 0, nullptr, EBPF_ANY, 0) == EBPF_OPERATION_NOT_SUPPORTED);

    REQUIRE(ebpf_map_get_program_from_entry(map.get(), sizeof(&key), reinterpret_cast<uint8_t*>(&key)) == nullptr);
    REQUIRE(ebpf_map_get_program_from_entry(map.get(), 0, 0) == nullptr);

    REQUIRE(
        ebpf_map_find_entry(map.get(), sizeof(key), reinterpret_cast<uint8_t*>(&key), 0, nullptr, 0) ==
        EBPF_INVALID_ARGUMENT);
    REQUIRE(
        ebpf_map_find_entry(map.get(), 0, nullptr, sizeof(value2), reinterpret_cast<uint8_t*>(&value2), 0) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(ebpf_map_find_entry(map.get(), 0, nullptr, 0, nullptr, 0) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_map_delete_entry(map.get(), 0, nullptr, 0) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_map_next_key(map.get(), 0, nullptr, nullptr) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_map_push_entry(map.get(), 0, nullptr, 0) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_map_pop_entry(map.get(), 0, nullptr, 0) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_map_peek_entry(map.get(), 0, nullptr, 0) == EBPF_OPERATION_NOT_SUPPORTED);
}

struct perf_event_array_test_async_context_t
{
    uint8_t* buffer = NULL;
    uint32_t buffer_size = 0;
    uint32_t cpu_id = 0;
    size_t consumer_offset = 0; // Offset of the consumer.
    size_t offset_mismatch_count = 0;
    size_t callback_count = 0;   // Number of callbacks received.
    size_t record_count = 0;     // Number of records consumed.
    size_t bad_record_count = 0; // Number of invalid records seen.
    size_t empty_callbacks = 0;  // Number of times we got a callback but there was no record.
    size_t discard_count = 0;    // Number of discarded records seen (should always be zero for perf event array).
    size_t locked_count =
        0; // Number of times we stopped reading because we saw a locked record instead of reaching the producer offset.
    size_t lost_count = 0;   // Number of lost records.
    size_t cancel_count = 0; // Number of times we were canceled.
    uint64_t value = 0;      // Value of the record consumed.
    ebpf_map_async_query_result_t async_query_result = {0};
};

/**
 * @brief Callback function for async query completion.
 *
 * Collects counts for verifying the test.
 *
 * @param context The test context.
 * @param output_buffer_length The length of the output buffer.
 * @param result The result of the async query.
 */
void
perf_event_array_test_async_complete(_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result)
{
    UNREFERENCED_PARAMETER(output_buffer_length);
    auto test_context = reinterpret_cast<perf_event_array_test_async_context_t*>(context);
    auto async_query_result = &test_context->async_query_result;
    test_context->callback_count++;
    test_context->lost_count += async_query_result->lost_count;

    if (result != EBPF_SUCCESS) {
        REQUIRE(result == EBPF_CANCELED);
        test_context->cancel_count++;
        return;
    }

    if (async_query_result->consumer != test_context->consumer_offset) {
        test_context->offset_mismatch_count++;
        test_context->consumer_offset = async_query_result->consumer;
    }
    size_t consumer_offset = test_context->consumer_offset;
    size_t producer_offset = async_query_result->producer;

    size_t record_count = 0;
    size_t discard_count = 0; // This should always be zero for perf event array.
    while (auto record = ebpf_ring_buffer_next_record(
               test_context->buffer, test_context->buffer_size, consumer_offset, producer_offset)) {
        if (ebpf_ring_buffer_record_is_locked(record)) {
            test_context->locked_count++;
            break;
        }
        if (ebpf_ring_buffer_record_is_discarded(record)) {
            discard_count++; // Should always be zero for perf event array.
        } else {
            record_count++;
        }
        if (ebpf_ring_buffer_record_length(record) != sizeof(uint64_t)) {
            test_context->bad_record_count++;
        } else {
            test_context->value = *(uint64_t*)(record->data);
        }
        consumer_offset += ebpf_ring_buffer_record_total_size(record);
    }
    test_context->consumer_offset = consumer_offset;
    test_context->record_count += record_count;
    test_context->discard_count += discard_count;
    if (record_count == 0) {
        test_context->empty_callbacks++;
    }
}

TEST_CASE("perf_event_array_output", "[execution_context][perf_event_array]")
{
    _ebpf_core_initializer core;
    core.initialize();
    uint32_t buffer_size = 64 * 1024;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_PERF_EVENT_ARRAY, 0, 0, buffer_size};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    uint32_t cpu_id = 0;
    scoped_cpu_affinity cpu_affinity(cpu_id);

    struct
    {
        EBPF_CONTEXT_HEADER; // Unused for this test.
        int unused;
    } context{0};

    void* ctx = &context.unused;

    uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU;

    perf_event_array_test_async_context_t completion;
    completion.cpu_id = cpu_id;
    completion.buffer_size = buffer_size;
    REQUIRE(ebpf_map_query_buffer(map.get(), cpu_id, &completion.buffer, &completion.consumer_offset) == EBPF_SUCCESS);
    REQUIRE(ebpf_async_set_completion_callback(&completion, perf_event_array_test_async_complete) == EBPF_SUCCESS);
    REQUIRE(completion.consumer_offset == 0);
    // Initialize consumer offset in async result used to track current position.
    completion.async_query_result.consumer = completion.consumer_offset;

    uint64_t value = 1;
    REQUIRE(
        ebpf_perf_event_array_map_output_with_capture(
            ctx, map.get(), flags, reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);

    ebpf_result_t result = ebpf_map_async_query(map.get(), cpu_id, &completion.async_query_result, &completion);
    if (result != EBPF_PENDING) { // If async query failed synchronously, reset the completion callback.
        REQUIRE(ebpf_async_reset_completion_callback(&completion) == EBPF_SUCCESS);
    }
    REQUIRE(result == EBPF_PENDING);

    REQUIRE(completion.callback_count == 1);
    REQUIRE(completion.lost_count == 0);
    REQUIRE(completion.record_count == 1);
    REQUIRE(completion.empty_callbacks == 0);
    REQUIRE(completion.discard_count == 0);
    REQUIRE(completion.locked_count == 0);
    REQUIRE(completion.offset_mismatch_count == 0);
    REQUIRE(completion.bad_record_count == 0);
    REQUIRE(completion.cancel_count == 0);
    uint64_t producer_offset = completion.async_query_result.producer;
    uint64_t consumer_offset = completion.async_query_result.consumer;
    REQUIRE(consumer_offset == 0);
    REQUIRE(completion.consumer_offset == producer_offset);
    REQUIRE(producer_offset == ((EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data) + sizeof(uint64_t) + 7) & ~7));
    REQUIRE(ebpf_map_return_buffer(map.get(), cpu_id, completion.consumer_offset - consumer_offset) == EBPF_SUCCESS);

    REQUIRE(completion.value == value);
}

TEST_CASE("perf_event_array_output_percpu", "[execution_context][perf_event_array]")
{
    _ebpf_core_initializer core;
    core.initialize();
    constexpr uint32_t buffer_size = 64 * 1024;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_PERF_EVENT_ARRAY, 0, 0, buffer_size};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    uint32_t ring_count = ebpf_get_cpu_count();
    std::vector<perf_event_array_test_async_context_t> completions(ring_count);

    auto cleanup = std::unique_ptr<void, std::function<void(void*)>>(
        reinterpret_cast<void*>(1), // Dummy pointer, we only care about the deleter.
        [&](void*) {
            // Cleanup - in unique_ptr scope guard to ensure cleanup on failure.
            // Note: In the success case all the operations will be completed, this handles fault injection cases.
            // Counters
            size_t cancel_count = 0;

            for (auto& completion : completions) {
                if (completion.buffer_size > 0) { // If buffer_size not set yet then we never started this query.
                    // We try canceling each operation, but only ones that haven't completed will actually cancel.
                    bool cancel_result = ebpf_async_cancel(&completion);
                    if (cancel_result == true) {
                        cancel_count++;
                    }
                    CHECK(cancel_result == false);
                }
            }
            REQUIRE(cancel_count == 0);
        });

    // Map each ring and set up completion callbacks.
    for (uint32_t cpu_id = 0; cpu_id < ring_count; cpu_id++) {
        auto& completion = completions[cpu_id];
        completion.cpu_id = cpu_id;

        // Map the ring buffer for the current CPU.
        REQUIRE(
            ebpf_map_query_buffer(map.get(), cpu_id, &completion.buffer, &completion.consumer_offset) == EBPF_SUCCESS);

        // Initialize the async query result.
        completion.async_query_result.consumer = completion.consumer_offset;

        // Set up the completion callback.
        REQUIRE(ebpf_async_set_completion_callback(&completion, perf_event_array_test_async_complete) == EBPF_SUCCESS);

        completion.buffer_size =
            buffer_size; // After this point this completion callback will be cleaned up on failure.

        // Start the async query.
        ebpf_result_t result = ebpf_map_async_query(map.get(), cpu_id, &completion.async_query_result, &completion);
        if (result != EBPF_PENDING) { // If async query failed synchronously, reset the completion callback.
            REQUIRE(ebpf_async_reset_completion_callback(&completion) == EBPF_SUCCESS);
        }
        REQUIRE(result == EBPF_PENDING);
    }

    // Write the CPU ID to each ring.
    for (uint32_t cpu_id = 0; cpu_id < ring_count; cpu_id++) {
        scoped_cpu_affinity cpu_affinity(cpu_id);

        struct
        {
            EBPF_CONTEXT_HEADER; // Unused for this test.
            int unused;
        } context{0};

        void* ctx = &context.unused;

        uint64_t value = cpu_id;
        uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU;

        REQUIRE(
            ebpf_perf_event_array_map_output_with_capture(
                ctx, map.get(), flags, reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);
    }

    // Verify the value written to each ring.
    for (uint32_t cpu_id = 0; cpu_id < ring_count; cpu_id++) {
        auto& completion = completions[cpu_id];

        REQUIRE(completion.callback_count == 1);
        REQUIRE(completion.record_count == 1);
        REQUIRE(completion.value == cpu_id);
        REQUIRE(completion.lost_count == 0);
        REQUIRE(completion.empty_callbacks == 0);
        REQUIRE(completion.discard_count == 0);
        REQUIRE(completion.locked_count == 0);
        REQUIRE(completion.offset_mismatch_count == 0);
        REQUIRE(completion.bad_record_count == 0);
        REQUIRE(completion.cancel_count == 0);

        // Return the buffer space.
        REQUIRE(
            ebpf_map_return_buffer(
                map.get(), cpu_id, completion.consumer_offset - completion.async_query_result.consumer) ==
            EBPF_SUCCESS);
    }
}

TEST_CASE("perf_event_array_output_capture", "[execution_context][perf_event_array]")
{
    _ebpf_core_initializer core;
    core.initialize();
    constexpr uint32_t buffer_size = 64 * 1024;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_PERF_EVENT_ARRAY, 0, 0, buffer_size};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    uint32_t cpu_id = 0;
    scoped_cpu_affinity cpu_affinity(cpu_id);

    size_t consumer_offset = 0;
    uint8_t* buffer = nullptr;
    REQUIRE(ebpf_map_query_buffer(map.get(), 0, &buffer, &consumer_offset) == EBPF_SUCCESS);

    std::vector<uint8_t> test_context_data(64);
    for (size_t i = 0; i < test_context_data.size(); i++) {
        test_context_data[i] = static_cast<uint8_t>(i * 3);
    }
    struct
    {
        EBPF_CONTEXT_HEADER; // Unused for this test.
        uint8_t* data;
        uint8_t* data_end;
    } context{0};
    context.data = test_context_data.data();
    context.data_end = test_context_data.data() + test_context_data.size();

    void* ctx = &context.data;
    ebpf_context_descriptor_t context_descriptor = {0};
    context_descriptor.size = sizeof(context);
    context_descriptor.data = 0;
    context_descriptor.end = EBPF_OFFSET_OF(decltype(context), data_end) - EBPF_OFFSET_OF(decltype(context), data);

    ebpf_program_set_header_context_descriptor(&context_descriptor, ctx);

    uint64_t capture_length = 10;
    uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU |
                     ((capture_length << EBPF_MAP_FLAG_CTX_LENGTH_SHIFT) & EBPF_MAP_FLAG_CTX_LENGTH_MASK);

    perf_event_array_test_async_context_t completion;
    completion.cpu_id = cpu_id;
    completion.buffer_size = buffer_size;
    REQUIRE(ebpf_map_query_buffer(map.get(), cpu_id, &completion.buffer, &completion.consumer_offset) == EBPF_SUCCESS);
    REQUIRE(ebpf_async_set_completion_callback(&completion, perf_event_array_test_async_complete) == EBPF_SUCCESS);
    REQUIRE(completion.consumer_offset == 0);
    // Initialize consumer offset in async result used to track current position.
    completion.async_query_result.consumer = completion.consumer_offset;

    uint64_t value = 1;
    REQUIRE(
        ebpf_perf_event_array_map_output_with_capture(
            ctx, map.get(), flags, reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);

    ebpf_result_t result = ebpf_map_async_query(map.get(), cpu_id, &completion.async_query_result, &completion);
    if (result != EBPF_PENDING) { // If async query failed synchronously, reset the completion callback.
        REQUIRE(ebpf_async_reset_completion_callback(&completion) == EBPF_SUCCESS);
    }
    REQUIRE(result == EBPF_PENDING);

    uint64_t total_data_length = sizeof(value) + capture_length;
    CAPTURE(
        capture_length,
        completion.callback_count,
        completion.lost_count,
        completion.record_count,
        completion.empty_callbacks,
        completion.discard_count,
        completion.locked_count,
        completion.offset_mismatch_count,
        completion.bad_record_count,
        completion.cancel_count,
        completion.consumer_offset,
        completion.async_query_result.consumer,
        completion.async_query_result.producer);

    REQUIRE(completion.callback_count == 1);
    REQUIRE(completion.lost_count == 0);
    REQUIRE(completion.record_count == 1);
    REQUIRE(completion.empty_callbacks == 0);
    REQUIRE(completion.discard_count == 0);
    REQUIRE(completion.locked_count == 0);
    REQUIRE(completion.offset_mismatch_count == 0);
    REQUIRE(completion.bad_record_count == 1); // The completion code expects 8 bytes, we added capture.
    REQUIRE(completion.cancel_count == 0);
    uint64_t producer_offset = completion.async_query_result.producer;
    consumer_offset = completion.async_query_result.consumer;
    REQUIRE(consumer_offset == 0);
    REQUIRE(completion.consumer_offset == producer_offset);
    REQUIRE(producer_offset == ((EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data) + (total_data_length) + 7) & ~7));

    auto record =
        ebpf_ring_buffer_next_record(completion.buffer, completion.buffer_size, consumer_offset, producer_offset);
    REQUIRE(record != nullptr);
    // We already checked the header in the completion, so we don't need to check it again.
    REQUIRE(memcmp(record->data, &value, sizeof(value)) == 0);
    REQUIRE(memcmp(record->data + sizeof(value), test_context_data.data(), capture_length) == 0);

    REQUIRE(ebpf_map_return_buffer(map.get(), cpu_id, completion.consumer_offset - consumer_offset) == EBPF_SUCCESS);
}

TEST_CASE("context_descriptor_header", "[platform][perf_event_array]")
{
    // Confirm context descriptor header in program context works as expected.

    struct context_t
    {
        uint8_t* data;
        uint8_t* data_end;
    };
    // Full context includes EBPF_CONTEXT_HEADER plus the program accessible portion.
    struct full_context_t
    {
        EBPF_CONTEXT_HEADER;
        context_t ctx;
    } context;

    // ctx points to the bpf-program accessible portion (just after the header).
    void* ctx = &context.ctx;

    // The context descriptor tells the platform where to find the data pointers.
    ebpf_context_descriptor_t context_descriptor = {
        sizeof(context_t), EBPF_OFFSET_OF(context_t, data), EBPF_OFFSET_OF(context_t, data_end), -1};
    ebpf_program_set_header_context_descriptor(&context_descriptor, ctx);

    const ebpf_context_descriptor_t* test_ctx_descriptor;
    ebpf_program_get_header_context_descriptor(ctx, &test_ctx_descriptor);
    REQUIRE(test_ctx_descriptor == &context_descriptor);

    const uint8_t *data_start, *data_end;

    context_descriptor = {
        sizeof(context.ctx), EBPF_OFFSET_OF(context_t, data), EBPF_OFFSET_OF(context_t, data_end), -1};
    context.ctx.data = (uint8_t*)((void*)0x0123456789abcdef);
    context.ctx.data_end = (uint8_t*)((void*)0xfedcba9876543210);
    ebpf_program_get_context_data(ctx, &data_start, &data_end);
    REQUIRE(data_start == context.ctx.data);
    REQUIRE(data_end == context.ctx.data_end);
}

TEST_CASE("perf_event_array_async_query", "[execution_context][perf_event_array]")
{
    _ebpf_core_initializer core;
    core.initialize();
    constexpr uint32_t buffer_size = 64 * 1024;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_PERF_EVENT_ARRAY, 0, 0, buffer_size};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    struct _completion
    {
        uint8_t* buffer{};
        uint32_t buffer_size{};
        uint32_t cpu_id{};
        size_t consumer_offset = 0;
        size_t callback_count = 0;
        size_t record_count = 0;
        size_t norecord_count = 0;
        size_t lost_count = 0;
        size_t cancel_count = 0;
        uint64_t value = 0;
        ebpf_map_async_query_result_t async_query_result = {};
    };
    uint32_t ring_count = ebpf_get_cpu_count();
    std::vector<_completion> completions(ring_count);

    uint64_t value = 1;

    auto cleanup = std::unique_ptr<void, std::function<void(void*)>>(
        reinterpret_cast<void*>(1), // Dummy pointer, we only care about the deleter.
        [&](void*) {
            // Cleanup - in unique_ptr scope guard to ensure cleanup on failure.
            // This guard ensures cleanup on fault injection and also verifies the callback counters.
            // Counters
            size_t total_callback_count = 0;
            size_t total_record_count = 0;
            size_t total_norecord_count = 0;
            size_t total_lost_count = 0;
            size_t cancel_count = 0;

            for (auto& completion : completions) {
                if (completion.buffer_size > 0) { // If buffer_size not set yet then we never started this query.
                    CAPTURE(
                        completion.cpu_id,
                        completion.record_count,
                        completion.norecord_count,
                        completion.cancel_count,
                        completion.lost_count);
                    CHECK(completion.callback_count <= 1);
                    CHECK(completion.lost_count == 0);
                    // We try canceling each operation, but only ones that haven't completed will actually cancel.
                    bool must_cancel = completion.callback_count == 0;
                    bool cancel_result = ebpf_async_cancel(&completion);
                    if (cancel_result == true) {
                        cancel_count++;
                    }
                    CHECK(cancel_result == must_cancel);
                    total_callback_count += completion.callback_count;
                    total_record_count += completion.record_count;
                    total_norecord_count += completion.norecord_count;
                    total_lost_count += completion.lost_count;
                    if (completion.record_count > 0) {
                        // This was the ring that got the record.
                        CHECK(completion.record_count == 1);
                        CHECK(completion.value == value);
                    }
                }
            }
        });

    // Map each ring and set up completion callbacks.
    for (uint32_t cpu_id = 0; cpu_id < ring_count; cpu_id++) {
        auto& completion = completions[cpu_id];
        completion.cpu_id = cpu_id;
        // Map the ring memory.
        REQUIRE(
            ebpf_map_query_buffer(map.get(), completion.cpu_id, &completion.buffer, &completion.consumer_offset) ==
            EBPF_SUCCESS);

        // Set up the completion callback.
        REQUIRE(
            ebpf_async_set_completion_callback(
                &completion, [](_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result) {
                    UNREFERENCED_PARAMETER(output_buffer_length);
                    auto completion = reinterpret_cast<_completion*>(context);
                    auto async_query_result = &completion->async_query_result;
                    completion->callback_count++;
                    completion->lost_count += async_query_result->lost_count;
                    auto record = ebpf_ring_buffer_next_record(
                        completion->buffer,
                        completion->buffer_size,
                        async_query_result->consumer,
                        async_query_result->producer);
                    if (record == nullptr) {
                        completion->norecord_count++;
                    } else if (!ebpf_ring_buffer_record_is_locked(record)) {
                        completion->record_count++;
                        completion->value = *(uint64_t*)(record->data);
                    }
                    if (result != EBPF_SUCCESS) {
                        REQUIRE(result == EBPF_CANCELED);
                        completion->cancel_count++;
                    }
                }) == EBPF_SUCCESS);

        // Start the async query.
        ebpf_result_t result = ebpf_map_async_query(map.get(), cpu_id, &completion.async_query_result, &completion);
        if (result != EBPF_PENDING) { // If async query failed synchronously, reset the completion callback.
            REQUIRE(ebpf_async_reset_completion_callback(&completion) == EBPF_SUCCESS);
        }
        completion.buffer_size = buffer_size; // After we set buffer_size the query will be cleaned up on exit.
        REQUIRE(result == EBPF_PENDING);
    }

    // Confirm none of the completions have been called yet.
    for (auto& completion : completions) {
        REQUIRE(completion.callback_count == 0);
    }

    struct
    {
        EBPF_CONTEXT_HEADER; // Unused for this test.
        int unused;
    } context{0};

    void* ctx = &context.unused;

    // Write a single record.
    uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU;
    REQUIRE(
        ebpf_perf_event_array_map_output_with_capture(
            ctx, map.get(), flags, reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);

    // Cleanup and final checks will be done in the scope_exit block above.
}

TEST_CASE("EBPF_OPERATION_CREATE_MAP", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_create_map_request_t, data));
    std::vector<uint8_t> reply(sizeof(ebpf_operation_create_map_reply_t));
    auto create_map_request = reinterpret_cast<ebpf_operation_create_map_request_t*>(request.data());

    // Non-object map with object.
    create_map_request->ebpf_map_definition = _map_definitions["BPF_MAP_TYPE_ARRAY"];
    create_map_request->inner_map_handle = map_handles["BPF_MAP_TYPE_HASH"];
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_MAP, request, reply) == EBPF_INVALID_ARGUMENT);

    // Object map with no object.
    create_map_request->ebpf_map_definition = _map_definitions["BPF_MAP_TYPE_HASH_OF_MAPS"];
    create_map_request->inner_map_handle = ebpf_handle_invalid;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_MAP, request, reply) == EBPF_INVALID_FD);

    // Object map with bad handle.
    create_map_request->ebpf_map_definition = _map_definitions["BPF_MAP_TYPE_HASH_OF_MAPS"];
    create_map_request->inner_map_handle = ebpf_handle_invalid - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_MAP, request, reply) == EBPF_INVALID_OBJECT);

    // Object map with wrong handle type.
    create_map_request->ebpf_map_definition = _map_definitions["BPF_MAP_TYPE_HASH_OF_MAPS"];
    create_map_request->inner_map_handle = program_handles[0];
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_MAP, request, reply) == EBPF_INVALID_OBJECT);

    // Array of maps with incorrect value size.
    create_map_request->ebpf_map_definition = _map_definitions["BPF_MAP_TYPE_ARRAY_OF_MAPS"];
    create_map_request->ebpf_map_definition.value_size = 1;
    create_map_request->inner_map_handle = map_handles["BPF_MAP_TYPE_HASH"];
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_MAP, request, reply) == EBPF_INVALID_ARGUMENT);

    // Hash of maps with incorrect key size.
    create_map_request->ebpf_map_definition = _map_definitions["BPF_MAP_TYPE_HASH_OF_MAPS"];
    create_map_request->ebpf_map_definition.value_size = 1;
    create_map_request->inner_map_handle = map_handles["BPF_MAP_TYPE_HASH"];
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_MAP, request, reply) == EBPF_INVALID_ARGUMENT);

    // Array of programs with incorrect key size.
    create_map_request->ebpf_map_definition = _map_definitions["BPF_MAP_TYPE_PROG_ARRAY"];
    create_map_request->ebpf_map_definition.value_size = 1;
    create_map_request->inner_map_handle = program_handles[0];
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_MAP, request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_LOAD_NATIVE_MODULE", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_load_native_module_request_t, data) + 2);
    std::vector<uint8_t> reply(sizeof(ebpf_operation_load_native_module_reply_t));
    auto load_native_module_request = reinterpret_cast<ebpf_operation_load_native_module_request_t*>(request.data());
    load_native_module_request->module_id = {};

    // Invalid module id.
    REQUIRE(invoke_protocol(EBPF_OPERATION_LOAD_NATIVE_MODULE, request, reply) == EBPF_OBJECT_NOT_FOUND);

    request.resize(request.size() + 1);
    REQUIRE(invoke_protocol(EBPF_OPERATION_LOAD_NATIVE_MODULE, request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_MAP_FIND_ELEMENT", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_map_find_element_request_t, key));
    std::vector<uint8_t> reply(EBPF_OFFSET_OF(ebpf_operation_map_find_element_reply_t, value));
    auto map_find_element_request = reinterpret_cast<ebpf_operation_map_find_element_request_t*>(request.data());
    map_find_element_request->handle = program_handles[0];

    // Invalid handle.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_FIND_ELEMENT, request, reply) == EBPF_INVALID_OBJECT);

    map_find_element_request->handle = map_handles["BPF_MAP_TYPE_HASH"];

    // Invalid key_size.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_FIND_ELEMENT, request, reply) == EBPF_INVALID_ARGUMENT);

    request.resize(request.size() + 4);
    // Invalid value_size.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_FIND_ELEMENT, request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_MAP_UPDATE_ELEMENT", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_map_update_element_request_t, data));
    auto map_update_element_request = reinterpret_cast<ebpf_operation_map_update_element_request_t*>(request.data());
    map_update_element_request->handle = program_handles[0];

    // Invalid handle.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT, request) == EBPF_INVALID_OBJECT);

    map_update_element_request->handle = map_handles["BPF_MAP_TYPE_HASH"];

    // Invalid key_size.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT, request) == EBPF_ARITHMETIC_OVERFLOW);

    request.resize(request.size() + 4);

    // Invalid value_size.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT, request) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();

    {
        std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_map_update_element_with_handle_request_t, key));
        auto map_update_element_with_handle_request =
            reinterpret_cast<ebpf_operation_map_update_element_with_handle_request_t*>(request.data());
        map_update_element_with_handle_request->map_handle = program_handles[0];

        // Invalid handle.
        REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE, request) == EBPF_INVALID_OBJECT);

        map_update_element_with_handle_request->map_handle = map_handles["BPF_MAP_TYPE_HASH_OF_MAPS"];

        // Invalid key_size.
        REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE, request) == EBPF_INVALID_ARGUMENT);

        request.resize(request.size() + 4);
        map_update_element_with_handle_request =
            reinterpret_cast<ebpf_operation_map_update_element_with_handle_request_t*>(request.data());
        map_update_element_with_handle_request->value_handle = program_handles[0];

        // Invalid value handle.
        REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE, request) == EBPF_INVALID_OBJECT);
    }

    {
        std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_map_update_element_with_handle_request_t, key));
        auto map_update_element_with_handle_request =
            reinterpret_cast<ebpf_operation_map_update_element_with_handle_request_t*>(request.data());
        map_update_element_with_handle_request->map_handle = program_handles[0];

        // Invalid handle.
        REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE, request) == EBPF_INVALID_OBJECT);

        // Update handle to a valid value and check for null key.
        map_update_element_with_handle_request->map_handle = map_handles["BPF_MAP_TYPE_ARRAY_OF_MAPS"];
        REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE, request) == EBPF_INVALID_ARGUMENT);

        // Make key non-null but pass an invalid value (0).
        request.resize(request.size() + 4);
        map_update_element_with_handle_request =
            reinterpret_cast<ebpf_operation_map_update_element_with_handle_request_t*>(request.data());

        // Check invalid value handle.
        REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE, request) == EBPF_INVALID_OBJECT);

        map_update_element_with_handle_request->value_handle = program_handles[0];

        // Pass an invalid key value.
        uint32_t key = 0xFFFF;
        memcpy(&map_update_element_with_handle_request->key, &key, sizeof(uint32_t));
        REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE, request) != EBPF_SUCCESS);

        // Check invalid option value.
        key = 0x1;
        memcpy(&map_update_element_with_handle_request->key, &key, sizeof(uint32_t));
        map_update_element_with_handle_request->option = EBPF_NOEXIST;
        REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE, request) == EBPF_INVALID_ARGUMENT);
    }
}

TEST_CASE("EBPF_OPERATION_MAP_DELETE_ELEMENT", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_map_delete_element_request_t, key));
    auto map_delete_element_request = reinterpret_cast<ebpf_operation_map_delete_element_request_t*>(request.data());
    map_delete_element_request->handle = program_handles[0];

    // Invalid handle.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_DELETE_ELEMENT, request) == EBPF_INVALID_OBJECT);

    map_delete_element_request->handle = map_handles["BPF_MAP_TYPE_HASH"];

    // Invalid key_size.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_DELETE_ELEMENT, request) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_MAP_GET_NEXT_KEY", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key));
    std::vector<uint8_t> reply(EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_reply_t, next_key));
    auto map_get_next_key_request = reinterpret_cast<ebpf_operation_map_get_next_key_request_t*>(request.data());
    map_get_next_key_request->handle = program_handles[0];

    // Invalid handle.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_GET_NEXT_KEY, request, reply) == EBPF_INVALID_OBJECT);

    map_get_next_key_request->handle = map_handles["BPF_MAP_TYPE_HASH"];

    request.resize(request.size() + 3);

    // Invalid previous_key.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_GET_NEXT_KEY, request, reply) == EBPF_INVALID_ARGUMENT);

    request.resize(EBPF_OFFSET_OF(ebpf_operation_map_get_next_key_request_t, previous_key) + 4);

    // Invalid next_key.
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_GET_NEXT_KEY, request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_QUERY_PROGRAM_INFO", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    std::vector<uint8_t> reply(EBPF_OFFSET_OF(_ebpf_operation_query_program_info_reply, data));
    ebpf_operation_query_program_info_request_t query_program_info_request;

    query_program_info_request.handle = map_handles.begin()->second;

    // Invalid handle.
    REQUIRE(
        invoke_protocol(EBPF_OPERATION_QUERY_PROGRAM_INFO, query_program_info_request, reply) == EBPF_INVALID_OBJECT);

    query_program_info_request.handle = program_handles[0];

    // Reply too small.
    REQUIRE(
        invoke_protocol(EBPF_OPERATION_QUERY_PROGRAM_INFO, query_program_info_request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_UPDATE_PINNING", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_update_pinning_request_t, path));
    auto update_pinning_request = reinterpret_cast<ebpf_operation_update_pinning_request_t*>(request.data());
    update_pinning_request->handle = ebpf_handle_invalid;

    // Zero length path.
    REQUIRE(invoke_protocol(EBPF_OPERATION_UPDATE_PINNING, request) == EBPF_INVALID_ARGUMENT);

    request.resize(request.size() + 4);

    // Invalid handle.
    update_pinning_request = reinterpret_cast<ebpf_operation_update_pinning_request_t*>(request.data());
    update_pinning_request->handle = ebpf_handle_invalid - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_UPDATE_PINNING, request) == EBPF_INVALID_OBJECT);
}

TEST_CASE("EBPF_OPERATION_GET_PINNED_OBJECT", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_get_pinned_object_request_t, path));
    std::vector<uint8_t> reply(sizeof(ebpf_operation_get_pinned_object_reply_t));

    // Zero length path.
    REQUIRE(invoke_protocol(EBPF_OPERATION_GET_PINNED_OBJECT, request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_GET_PINNED_OBJECT short header", "[execution_context][negative]")
{
    _ebpf_core_initializer core;
    core.initialize();

    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_get_pinned_object_request_t, path));
    std::vector<uint8_t> reply(sizeof(ebpf_operation_get_pinned_object_reply_t));

    uint32_t request_size;
    void* request_ptr;
    uint32_t reply_size;
    void* reply_ptr;
    bool variable_reply_size = false;

    request_size = static_cast<uint32_t>(request.size());
    request_ptr = request.data();

    reply_size = static_cast<uint32_t>(reply.size());
    reply_ptr = reply.data();
    variable_reply_size = true;
    auto header = reinterpret_cast<ebpf_operation_header_t*>(request_ptr);
    header->id = EBPF_OPERATION_GET_PINNED_OBJECT;
    header->length = 4; // Less than sizeof(ebpf_operation_header_t).

    auto completion = [](void*, size_t, ebpf_result_t) {};

    REQUIRE(
        ebpf_core_invoke_protocol_handler(
            EBPF_OPERATION_GET_PINNED_OBJECT,
            request_ptr,
            static_cast<uint16_t>(request_size),
            reply_ptr,
            static_cast<uint16_t>(reply_size),
            nullptr,
            completion) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_LINK_PROGRAM", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_link_program_request_t, data));
    auto link_program_request = reinterpret_cast<ebpf_operation_link_program_request_t*>(request.data());
    ebpf_operation_link_program_reply_t reply;

    link_program_request->program_handle = map_handles.begin()->second;
    // Wrong handle type.
    REQUIRE(invoke_protocol(EBPF_OPERATION_LINK_PROGRAM, request, reply) == EBPF_INVALID_OBJECT);

    // No provider.
    link_program_request->program_handle = program_handles[0];
    REQUIRE(invoke_protocol(EBPF_OPERATION_LINK_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_GET_PROGRAM_INFO", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_get_program_info_request_t request;
    std::vector<uint8_t> reply(EBPF_OFFSET_OF(ebpf_operation_get_program_info_reply_t, data));

    request.program_handle = map_handles.begin()->second;
    // Invalid object type.
    REQUIRE(invoke_protocol(EBPF_OPERATION_GET_PROGRAM_INFO, request, reply) == EBPF_INVALID_OBJECT);

    // Invalid program handle and type.
    request.program_handle = ebpf_handle_invalid;
    request.program_type = {0};
    REQUIRE(invoke_protocol(EBPF_OPERATION_GET_PROGRAM_INFO, request, reply) == EBPF_INVALID_ARGUMENT);

    // Reply too small.
    request.program_handle = program_handles[0];
    REQUIRE(invoke_protocol(EBPF_OPERATION_GET_PROGRAM_INFO, request, reply) == EBPF_INSUFFICIENT_BUFFER);
}

TEST_CASE("EBPF_OPERATION_GET_PINNED_MAP_INFO", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_get_pinned_map_info_request_t request;
    std::vector<uint8_t> reply(EBPF_OFFSET_OF(ebpf_operation_get_pinned_map_info_reply_t, data));

    // No pinned maps.
    REQUIRE(invoke_protocol(EBPF_OPERATION_GET_PINNED_MAP_INFO, request, reply) == EBPF_SUCCESS);
}

TEST_CASE("EBPF_OPERATION_GET_OBJECT_INFO", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_get_object_info_request_t request;
    std::vector<uint8_t> reply(EBPF_OFFSET_OF(ebpf_operation_get_object_info_reply_t, info));

    request.handle = ebpf_handle_invalid - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_GET_OBJECT_INFO, request, reply) == EBPF_INVALID_OBJECT);
}

TEST_CASE("EBPF_OPERATION_MAP_QUERY_BUFFER", "[execution_context][ring_buffer][perf_event_array][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_map_query_buffer_request_t request;
    ebpf_operation_map_query_buffer_reply_t reply;

    request.map_handle = ebpf_handle_invalid - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_QUERY_BUFFER, request, reply) == EBPF_INVALID_OBJECT);

    request.map_handle = map_handles.begin()->second;
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_QUERY_BUFFER, request, reply) == EBPF_OPERATION_NOT_SUPPORTED);
}

TEST_CASE("EBPF_OPERATION_MAP_ASYNC_QUERY", "[execution_context][ring_buffer][perf_event_array][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_map_async_query_request_t request;
    ebpf_operation_map_async_query_reply_t reply;
    int async = 1;

    request.map_handle = ebpf_handle_invalid - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_ASYNC_QUERY, request, reply, &async) == EBPF_INVALID_OBJECT);

    request.map_handle = map_handles["BPF_MAP_TYPE_HASH"];
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_ASYNC_QUERY, request, reply, &async) == EBPF_OPERATION_NOT_SUPPORTED);
}

TEST_CASE("EBPF_OPERATION_LOAD_NATIVE_MODULE short header", "[execution_context][negative]")
{
    _ebpf_core_initializer core;
    core.initialize();

    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_load_native_module_request_t, data));
    std::vector<uint8_t> reply(sizeof(ebpf_operation_load_native_module_reply_t));

    uint32_t request_size;
    void* request_ptr;
    uint32_t reply_size;
    void* reply_ptr;
    bool variable_reply_size = false;

    request_size = static_cast<uint32_t>(request.size());
    request_ptr = request.data();

    reply_size = static_cast<uint32_t>(reply.size());
    reply_ptr = reply.data();
    variable_reply_size = true;
    auto header = reinterpret_cast<ebpf_operation_header_t*>(request_ptr);
    header->id = EBPF_OPERATION_LOAD_NATIVE_MODULE;
    header->length = 12; // Less than sizeof(ebpf_operation_load_native_module_request_t).

    auto completion = [](void*, size_t, ebpf_result_t) {};

    REQUIRE(
        ebpf_core_invoke_protocol_handler(
            EBPF_OPERATION_LOAD_NATIVE_MODULE,
            request_ptr,
            static_cast<uint16_t>(request_size),
            reply_ptr,
            static_cast<uint16_t>(reply_size),
            nullptr,
            completion) == EBPF_ARITHMETIC_OVERFLOW);
}

#define EBPF_PROGRAM_TYPE_TEST_GUID                                                    \
    {                                                                                  \
        0x8ee1b757, 0xc0b2, 0x4c84, { 0xac, 0x07, 0x0c, 0x76, 0x29, 0x8f, 0x1d, 0xc9 } \
    }

void
test_register_provider(
    _In_ const NPI_PROVIDER_CHARACTERISTICS* provider_characteristics, bool expected_to_succeed = false)
{
    class provider_deregister_helper
    {
      public:
        void
        operator()(HANDLE handle)
        {
            NmrDeregisterProvider(handle);
        }
    };

    typedef std::unique_ptr<void, provider_deregister_helper> provider_ptr;
    provider_ptr provider;
    HANDLE nmr_provider_handle;

    REQUIRE(NmrRegisterProvider(provider_characteristics, nullptr, &nmr_provider_handle) == STATUS_SUCCESS);
    provider.reset(nmr_provider_handle);

    ebpf_program_type_t EBPF_PROGRAM_TYPE_TEST = EBPF_PROGRAM_TYPE_TEST_GUID;
    const cxplat_utf8_string_t program_name{(uint8_t*)("foo"), 3};
    const cxplat_utf8_string_t section_name{(uint8_t*)("bar"), 3};
    const ebpf_program_parameters_t program_parameters{
        EBPF_PROGRAM_TYPE_TEST, EBPF_ATTACH_TYPE_SAMPLE, program_name, section_name};
    program_ptr program;
    {
        ebpf_program_t* local_program = nullptr;
        REQUIRE(
            ebpf_program_create(&program_parameters, &local_program) ==
            (expected_to_succeed ? EBPF_SUCCESS : EBPF_EXTENSION_FAILED_TO_LOAD));
        program.reset(local_program);
        if (expected_to_succeed) {
            helper_function_address_t addresses[1] = {};
            uint32_t helper_function_ids[] = {EBPF_MAX_GENERAL_HELPER_FUNCTION + 1};
            REQUIRE(
                ebpf_program_set_helper_function_ids(
                    program.get(), EBPF_COUNT_OF(helper_function_ids), helper_function_ids) == EBPF_SUCCESS);
            REQUIRE(
                ebpf_program_get_helper_function_addresses(
                    program.get(), EBPF_COUNT_OF(helper_function_ids), addresses) == EBPF_SUCCESS);
            REQUIRE(addresses[0].address != 0);
        }
    }
}

TEST_CASE("INVALID_PROGRAM_DATA", "[execution_context][negative]")
{
    _ebpf_core_initializer core;
    core.initialize();

    ebpf_context_descriptor_t _test_context_descriptor = {sizeof(ebpf_context_descriptor_t), -1, -1, -1};

    const uint32_t _test_prog_type = 1000;
    ebpf_program_type_descriptor_t _test_program_type_descriptor = {
        EBPF_PROGRAM_TYPE_DESCRIPTOR_HEADER,
        "test_program_type",
        &_test_context_descriptor,
        EBPF_PROGRAM_TYPE_TEST_GUID,
        _test_prog_type,
        0};

    ebpf_helper_function_prototype_t _test_helper_function_prototype[] = {
        {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
         EBPF_MAX_GENERAL_HELPER_FUNCTION + 1,
         "test_helper_function",
         EBPF_RETURN_TYPE_INTEGER,
         {EBPF_ARGUMENT_TYPE_DONTCARE}}};

    ebpf_program_info_t _test_program_info = {
        EBPF_PROGRAM_INFORMATION_HEADER,
        &_test_program_type_descriptor,
        EBPF_COUNT_OF(_test_helper_function_prototype),
        _test_helper_function_prototype};

    auto provider_function1 = []() { return (ebpf_result_t)TEST_FUNCTION_RETURN; };
    ebpf_result_t (*function_pointer1)() = provider_function1;
    const void* helper_functions[] = {(void*)function_pointer1};
    ebpf_helper_function_addresses_t helper_function_addresses = {
        EBPF_HELPER_FUNCTION_ADDRESSES_HEADER, EBPF_COUNT_OF(helper_functions), (uint64_t*)helper_functions};

    ebpf_program_data_t _test_program_data = {
        EBPF_PROGRAM_DATA_HEADER, &_test_program_info, &helper_function_addresses, nullptr, nullptr, nullptr, 0, {0}};

    auto provider_attach_client_callback =
        [](HANDLE, void*, const NPI_REGISTRATION_INSTANCE*, void*, const void*, void**, const void**) -> NTSTATUS {
        return STATUS_SUCCESS;
    };
    auto provider_detach_client_callback = [](void*) -> NTSTATUS { return STATUS_SUCCESS; };

    NPI_MODULEID module_id = {sizeof(NPI_MODULEID), MIT_GUID, EBPF_PROGRAM_TYPE_TEST_GUID};

    NPI_PROVIDER_CHARACTERISTICS provider_characteristics{
        0,
        sizeof(NPI_PROVIDER_CHARACTERISTICS),
        provider_attach_client_callback,
        provider_detach_client_callback,
        nullptr,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &EBPF_PROGRAM_INFO_EXTENSION_IID,
            &module_id,
            0,
            &_test_program_data,
        },
    };

    // Register the provider with valid program data. The test is expected to succeed.
    bool expected_to_succeed = true;
    test_register_provider(&provider_characteristics, expected_to_succeed);

    // In the next tests, exactly one field of the program data will be invalidated. The tests are expected to fail.

    // Set bad version for program data header.
    _test_program_data.header.version = 0;
    test_register_provider(&provider_characteristics);
    // Restore.
    _test_program_data.header.version = EBPF_PROGRAM_DATA_CURRENT_VERSION;

    // Set bigger size than supported for the program data header.
    _test_program_data.header.size = EBPF_PROGRAM_DATA_CURRENT_VERSION_SIZE + 1;
    test_register_provider(&provider_characteristics);
    // Restore.
    _test_program_data.header.size = EBPF_PROGRAM_DATA_CURRENT_VERSION_SIZE;

    // Remove the program data from the provider characteristics struct.
    provider_characteristics.ProviderRegistrationInstance.NpiSpecificCharacteristics = nullptr;
    test_register_provider(&provider_characteristics);
    // Restore.
    provider_characteristics.ProviderRegistrationInstance.NpiSpecificCharacteristics = &_test_program_data;

    // Remove the address from the helper function.
    helper_function_addresses.helper_function_address = nullptr;
    test_register_provider(&provider_characteristics);
    // Restore.
    helper_function_addresses.helper_function_address = (uint64_t*)helper_functions;

    // Remove the program info struct from the program data.
    _test_program_data.program_info = nullptr;
    test_register_provider(&provider_characteristics);
    // Restore.
    _test_program_data.program_info = &_test_program_info;

    // Remove the program type descriptor from the program info.
    _test_program_info.program_type_descriptor = nullptr;
    test_register_provider(&provider_characteristics);
    // Restore.
    _test_program_info.program_type_descriptor = &_test_program_type_descriptor;

    // Remove name to the program type descriptor.
    _test_program_type_descriptor.name = nullptr;
    test_register_provider(&provider_characteristics);
    // Restore.
    _test_program_type_descriptor.name = "test_program_type";

    // Remove the context descriptor from the program type descriptor.
    _test_program_type_descriptor.context_descriptor = nullptr;
    test_register_provider(&provider_characteristics);
    // Restore.
    _test_program_type_descriptor.context_descriptor = &_test_context_descriptor;

    // Invalidate the context descriptor (size = 0).
    _test_context_descriptor.size = 0;
    test_register_provider(&provider_characteristics);
    // Fix up the context descriptor.
    _test_context_descriptor.size = sizeof(ebpf_context_descriptor_t);

    // Remove the helper function prototype from the program info.
    _test_program_info.program_type_specific_helper_prototype = nullptr;
    test_register_provider(&provider_characteristics);
    // Restore.
    _test_program_info.program_type_specific_helper_prototype = _test_helper_function_prototype;

    // Invalidate the helper function prototype by removing the name of the helper function.
    _test_helper_function_prototype[0].name = nullptr;
    test_register_provider(&provider_characteristics);
}

// TODO: Add more native module loading IOCTL negative tests.
// https://github.com/microsoft/ebpf-for-windows/issues/1139
// EBPF_OPERATION_LOAD_NATIVE_MODULE
// EBPF_OPERATION_LOAD_NATIVE_PROGRAMS
