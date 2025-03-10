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
#include "helpers.h"
#include "test_helper.hpp"

#include <iomanip>
#include <optional>
#include <set>

#if !defined(CONFIG_BPF_JIT_DISABLED)
typedef struct _free_trampoline_table
{
    void
    operator()(_In_opt_ _Post_invalid_ ebpf_trampoline_table_t* table)
    {
        if (table != nullptr) {
            ebpf_free_trampoline_table(table);
        }
    }
} free_trampoline_table_t;

typedef std::unique_ptr<ebpf_trampoline_table_t, free_trampoline_table_t> ebpf_trampoline_table_ptr;
#endif

typedef class _ebpf_async_wrapper
{
  public:
    _ebpf_async_wrapper()
    {
        _event = CreateEvent(nullptr, false, false, nullptr);
        if (_event == INVALID_HANDLE_VALUE) {
            throw std::bad_alloc();
        }
        if (ebpf_async_set_completion_callback(this, _ebpf_async_wrapper::completion_callback) != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_async_set_completion_callback failed");
        }
    }
    ~_ebpf_async_wrapper()
    {
        if (!_completed) {
            ebpf_async_complete(this, 0, EBPF_CANCELED);
        }
    }

    ebpf_result_t
    get_result()
    {
        return _result;
    }

    bool
    get_completed()
    {
        return _completed;
    }

    size_t
    get_reply_size()
    {
        return _reply_size;
    }

    void
    wait()
    {
        REQUIRE(WaitForSingleObject(_event, INFINITE) == WAIT_OBJECT_0);
    }

  private:
    static void
    completion_callback(_In_ void* context, size_t reply_size, ebpf_result_t result)
    {
        ebpf_async_wrapper_t* async_wrapper = (ebpf_async_wrapper_t*)context;
        async_wrapper->_result = result;
        async_wrapper->_reply_size = reply_size;
        async_wrapper->_completed = true;
        SetEvent(async_wrapper->_event);
    }
    ebpf_result_t _result = EBPF_SUCCESS;
    size_t _reply_size = 0;
    bool _completed = false;
    HANDLE _event;
} ebpf_async_wrapper_t;

class _ebpf_core_initializer
{
  public:
    void
    initialize()
    {
        REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    }
    ~_ebpf_core_initializer() { ebpf_core_terminate(); }
};

template <typename T> class ebpf_object_deleter
{
  public:
    void
    operator()(T* object)
    {
        EBPF_OBJECT_RELEASE_REFERENCE(reinterpret_cast<ebpf_core_object_t*>(object));
    }
};

typedef std::unique_ptr<ebpf_map_t, ebpf_object_deleter<ebpf_map_t>> map_ptr;
typedef std::unique_ptr<ebpf_program_t, ebpf_object_deleter<ebpf_program_t>> program_ptr;
typedef std::unique_ptr<ebpf_link_t, ebpf_object_deleter<ebpf_link_t>> link_ptr;

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

#define TEST_FUNCTION_RETURN 42
#define TOTAL_HELPER_COUNT 3

uint32_t
test_function()
{
    return TEST_FUNCTION_RETURN;
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("program", "[execution_context]")
{
    // single_instance_hook_t call ebpapi functions, which requires calling ebpf_api_initiate/ebpf_api_terminate.
    _test_helper_end_to_end end_to_end;
    end_to_end.initialize();

    program_info_provider_t program_info_provider;
    REQUIRE(program_info_provider.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    const cxplat_utf8_string_t program_name{(uint8_t*)("foo"), 3};
    const cxplat_utf8_string_t section_name{(uint8_t*)("bar"), 3};
    const ebpf_program_parameters_t program_parameters{
        EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE, program_name, section_name};
    program_ptr program;
    {
        ebpf_program_t* local_program = nullptr;
        REQUIRE(ebpf_program_create(&program_parameters, &local_program) == EBPF_SUCCESS);
        program.reset(local_program);
    }

    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint64_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    ebpf_program_info_t* program_info;

    ebpf_program_type_t returned_program_type = ebpf_program_type_uuid(program.get());
    REQUIRE(
        memcmp(&program_parameters.program_type, &returned_program_type, sizeof(program_parameters.program_type)) == 0);

    REQUIRE(ebpf_program_get_program_info(program.get(), &program_info) == EBPF_SUCCESS);
    REQUIRE(program_info != nullptr);
    ebpf_program_free_program_info(program_info);

    ebpf_map_t* maps[] = {map.get()};

    REQUIRE(((ebpf_core_object_t*)map.get())->base.reference_count == 1);
    REQUIRE(ebpf_program_associate_maps(program.get(), maps, EBPF_COUNT_OF(maps)) == EBPF_SUCCESS);
    REQUIRE(((ebpf_core_object_t*)map.get())->base.reference_count == 2);

    ebpf_trampoline_table_ptr table;
    ebpf_result_t (*test_function)();
    auto provider_function1 = []() { return (ebpf_result_t)TEST_FUNCTION_RETURN; };
    ebpf_result_t (*function_pointer1)() = provider_function1;
    uint32_t test_function_ids[] = {(EBPF_MAX_GENERAL_HELPER_FUNCTION + 1)};
    const void* helper_functions[] = {(void*)function_pointer1};
    ebpf_helper_function_addresses_t helper_function_addresses = {
        EBPF_HELPER_FUNCTION_ADDRESSES_HEADER, EBPF_COUNT_OF(helper_functions), (uint64_t*)helper_functions};

    {
        ebpf_trampoline_table_t* local_table = nullptr;
        REQUIRE(ebpf_allocate_trampoline_table(1, &local_table) == EBPF_SUCCESS);
        table.reset(local_table);
    }
    REQUIRE(
        ebpf_update_trampoline_table(
            table.get(), EBPF_COUNT_OF(test_function_ids), test_function_ids, &helper_function_addresses) ==
        EBPF_SUCCESS);
    REQUIRE(
        ebpf_get_trampoline_function(
            table.get(), EBPF_MAX_GENERAL_HELPER_FUNCTION + 1, reinterpret_cast<void**>(&test_function)) ==
        EBPF_SUCCESS);

    // Size of the actual function is unknown, but we know the allocation is on page granularity.
    REQUIRE(
        ebpf_program_load_code(
            program.get(), EBPF_CODE_JIT, nullptr, reinterpret_cast<uint8_t*>(test_function), PAGE_SIZE) ==
        EBPF_SUCCESS);
    uint32_t result = 0;
    sample_program_context_header_t ctx_header{0};
    sample_program_context_t* ctx = &ctx_header.context;

    ebpf_execution_context_state_t state{};
    ebpf_get_execution_context_state(&state);
    ebpf_result_t ebpf_result = ebpf_program_invoke(program.get(), ctx, &result, &state);
    REQUIRE(ebpf_result == EBPF_SUCCESS);
    REQUIRE(result == TEST_FUNCTION_RETURN);

    ebpf_program_test_run_options_t options = {0};
    sample_program_context_t in_ctx{0};
    sample_program_context_t out_ctx{0};
    options.repeat_count = 10;
    options.context_in = reinterpret_cast<uint8_t*>(&in_ctx);
    options.context_size_in = sizeof(in_ctx);
    options.context_out = reinterpret_cast<uint8_t*>(&out_ctx);
    options.context_size_out = sizeof(out_ctx);

    ebpf_async_wrapper_t async_context;
    uint64_t unused_completion_context = 0;

    REQUIRE(
        ebpf_program_execute_test_run(
            program.get(),
            &options,
            &async_context,
            &unused_completion_context,
            [](_In_ ebpf_result_t result,
               _In_ const ebpf_program_t* program,
               _In_ const ebpf_program_test_run_options_t* options,
               _Inout_ void* completion_context,
               _Inout_ void* async_context) {
                ebpf_assert(program != nullptr);
                ebpf_assert(options != nullptr);
                ebpf_assert(completion_context != nullptr);
                ebpf_assert(async_context != nullptr);
                ebpf_async_complete(async_context, options->data_size_out, result);
            }) == EBPF_PENDING);

    async_context.wait();
    REQUIRE(async_context.get_result() == EBPF_SUCCESS);
    REQUIRE(async_context.get_completed() == true);

    REQUIRE(options.return_value == TEST_FUNCTION_RETURN);
    REQUIRE(options.duration > 0);

    helper_function_address_t addresses[TOTAL_HELPER_COUNT] = {};
    uint32_t helper_function_ids[] = {1, 3, 2};
    REQUIRE(
        ebpf_program_set_helper_function_ids(program.get(), EBPF_COUNT_OF(helper_function_ids), helper_function_ids) ==
        EBPF_SUCCESS);
    REQUIRE(
        ebpf_program_get_helper_function_addresses(program.get(), EBPF_COUNT_OF(helper_function_ids), addresses) ==
        EBPF_SUCCESS);
    REQUIRE(addresses[0].address != 0);
    REQUIRE(addresses[1].address != 0);
    REQUIRE(addresses[2].address != 0);

    link_ptr link;

    // Correct attach type, but wrong program type.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        ebpf_link_t* local_link = nullptr;
        REQUIRE(ebpf_link_create(EBPF_ATTACH_TYPE_SAMPLE, nullptr, 0, &local_link) == EBPF_SUCCESS);
        link.reset(local_link);
        REQUIRE(ebpf_link_attach_program(link.get(), program.get()) == EBPF_EXTENSION_FAILED_TO_LOAD);
    }

    // Wrong attach type, but correct program type.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_BIND);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        ebpf_link_t* local_link = nullptr;
        REQUIRE(ebpf_link_create(EBPF_ATTACH_TYPE_SAMPLE, nullptr, 0, &local_link) == EBPF_SUCCESS);
        link.reset(local_link);
        REQUIRE(ebpf_link_attach_program(link.get(), program.get()) == EBPF_EXTENSION_FAILED_TO_LOAD);
    }

    // Correct attach type and correct program type.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        ebpf_link_t* local_link = nullptr;
        REQUIRE(ebpf_link_create(EBPF_ATTACH_TYPE_SAMPLE, nullptr, 0, &local_link) == EBPF_SUCCESS);
        link.reset(local_link);

        // Attach should succeed.
        REQUIRE(ebpf_link_attach_program(link.get(), program.get()) == EBPF_SUCCESS);

        // Not possible to attach again.

        // First detach should succeed.
        ebpf_link_detach_program(link.get());

        // Second detach should be no-op.
        ebpf_link_detach_program(link.get());
    }

    link.reset();

    ebpf_free_trampoline_table(table.release());
}
#endif

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
        size_t consumer_offset = 0;
        ebpf_ring_buffer_map_async_query_result_t async_query_result = {};
        volatile uint64_t value{};
    } completion;

    REQUIRE(
        ebpf_ring_buffer_map_query_buffer(map.get(), &completion.buffer, &completion.consumer_offset) == EBPF_SUCCESS);
    // Initialize consumer offset in async result used to track current position.
    completion.async_query_result.consumer = completion.consumer_offset;

    REQUIRE(
        ebpf_async_set_completion_callback(
            &completion, [](_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result) {
                UNREFERENCED_PARAMETER(output_buffer_length);
                auto completion = reinterpret_cast<_completion*>(context);
                auto async_query_result = &completion->async_query_result;
                auto record = ebpf_ring_buffer_next_record(
                    completion->buffer, sizeof(uint64_t), async_query_result->consumer, async_query_result->producer);
                completion->value = *(uint64_t*)(record->data);
                REQUIRE(result == EBPF_SUCCESS);
            }) == EBPF_SUCCESS);

    ebpf_result_t result = ebpf_ring_buffer_map_async_query(map.get(), &completion.async_query_result, &completion);
    if (result != EBPF_PENDING) {
        REQUIRE(ebpf_async_reset_completion_callback(&completion) == EBPF_SUCCESS);
    }
    REQUIRE(result == EBPF_PENDING);

    uint64_t value = 1;
    REQUIRE(ebpf_ring_buffer_map_output(map.get(), reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);

    REQUIRE(completion.value == value);

    {
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
    {
        "BPF_MAP_TYPE_STACK",
        {
            BPF_MAP_TYPE_PERCPU_ARRAY,
            0,
            20,
            10,
        },
    },
};

void
create_various_objects(std::vector<ebpf_handle_t>& program_handles, std::map<std::string, ebpf_handle_t>& map_handles)
{
    for (const auto& type : _program_types) {
        std::string name = "program name";
        std::string file = "file name";
        std::string section = "section name";
        ebpf_program_parameters_t params{
            type,
            type,
            {reinterpret_cast<uint8_t*>(name.data()), name.size()},
            {reinterpret_cast<uint8_t*>(section.data()), section.size()},
            {reinterpret_cast<uint8_t*>(file.data()), file.size()},
            EBPF_CODE_NONE};
        ebpf_handle_t handle;
        REQUIRE(ebpf_program_create_and_initialize(&params, &handle) == EBPF_SUCCESS);
        program_handles.push_back(handle);
    }
    for (const auto& [name, def] : _map_definitions) {
        cxplat_utf8_string_t utf8_name{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())), name.size()};
        ebpf_handle_t handle;
        ebpf_handle_t inner_handle = ebpf_handle_invalid;
        if (def.inner_map_id != 0) {
            inner_handle = map_handles.begin()->second;
        }
        REQUIRE(ebpf_core_create_map(&utf8_name, &def, inner_handle, &handle) == EBPF_SUCCESS);
        map_handles.insert({name, handle});
    }
}

typedef struct empty_reply
{
} empty_reply_t;

static empty_reply_t _empty_reply;
typedef std::vector<uint8_t> ebpf_protocol_buffer_t;

template <typename request_t, typename reply_t = empty_reply_t>
_Must_inspect_result_ ebpf_result_t
invoke_protocol(
    ebpf_operation_id_t operation_id,
    request_t& request,
    reply_t& reply = _empty_reply,
    _Inout_opt_ void* async = nullptr)
{
    uint32_t request_size;
    void* request_ptr;
    uint32_t reply_size;
    void* reply_ptr;
    bool variable_reply_size = false;

    if constexpr (std::is_same<request_t, nullptr_t>::value) {
        request_size = 0;
        request_ptr = nullptr;
    } else if constexpr (std::is_same<request_t, ebpf_protocol_buffer_t>::value) {
        request_size = static_cast<uint32_t>(request.size());
        request_ptr = request.data();
    } else {
        request_size = sizeof(request);
        request_ptr = &request;
    }

    if constexpr (std::is_same<reply_t, nullptr_t>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    } else if constexpr (std::is_same<reply_t, ebpf_protocol_buffer_t>::value) {
        reply_size = static_cast<uint32_t>(reply.size());
        reply_ptr = reply.data();
        variable_reply_size = true;
    } else if constexpr (std::is_same<reply_t, empty_reply>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    } else {
        reply_size = static_cast<uint32_t>(sizeof(reply));
        reply_ptr = &reply;
    }
    auto header = reinterpret_cast<ebpf_operation_header_t*>(request_ptr);
    header->id = operation_id;
    header->length = static_cast<uint16_t>(request_size);

    auto completion = [](void*, size_t, ebpf_result_t) {};

    return ebpf_core_invoke_protocol_handler(
        operation_id,
        request_ptr,
        static_cast<uint16_t>(request_size),
        reply_ptr,
        static_cast<uint16_t>(reply_size),
        async,
        completion);
}

extern bool _ebpf_platform_code_integrity_enabled;

#define NEGATIVE_TEST_PROLOG()                                                        \
    _ebpf_core_initializer core;                                                      \
    core.initialize();                                                                \
    std::vector<std::unique_ptr<_program_info_provider>> program_info_providers;      \
    for (const auto& type : _program_types) {                                         \
        program_info_providers.push_back(std::make_unique<_program_info_provider>()); \
        REQUIRE(program_info_providers.back()->initialize(type) == EBPF_SUCCESS);     \
    }                                                                                 \
    std::vector<ebpf_handle_t> program_handles;                                       \
    std::map<std::string, ebpf_handle_t> map_handles;                                 \
    create_various_objects(program_handles, map_handles);

#if defined(CONFIG_BPF_JIT_DISABLED) || defined(CONFIG_BPF_INTERPRETER_DISABLED)
void
test_blocked_by_policy(ebpf_operation_id_t operation)
{
    NEGATIVE_TEST_PROLOG();

    ebpf_result_t expected_result = EBPF_BLOCKED_BY_POLICY;

    std::vector<uint8_t> request(sizeof(ebpf_operation_header_t));
    std::vector<uint8_t> reply(sizeof(ebpf_operation_header_t));

    REQUIRE(invoke_protocol(operation, request, reply) == expected_result);

    // Use a request buffer larger than ebpf_operation_header_t, and try again.
    request.resize(request.size() + 10);
    REQUIRE(invoke_protocol(operation, request, reply) == expected_result);
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
// These tests exist to verify ebpf_core's parsing of messages.
// See libbpf_test.cpp for invalid parameter but correctly formed message cases.
TEST_CASE("EBPF_OPERATION_RESOLVE_HELPER", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();

    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id) + sizeof(uint32_t));
    std::vector<uint8_t> reply(
        EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + sizeof(helper_function_address_t));
    auto resolve_helper_request = reinterpret_cast<ebpf_operation_resolve_helper_request_t*>(request.data());

    // Invalid handle.
    resolve_helper_request->program_handle = ebpf_handle_invalid;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_HELPER, request, reply) == EBPF_INVALID_OBJECT);

    // Invalid helper id.
    resolve_helper_request->program_handle = program_handles[0];
    resolve_helper_request->helper_id[0] = UINT32_MAX;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_HELPER, request, reply) == EBPF_INVALID_ARGUMENT);

    reply.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address));
    // Reply too small.
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_HELPER, request, reply) == EBPF_INVALID_ARGUMENT);

    // Set no helper functions.
    request.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id));
    resolve_helper_request = reinterpret_cast<ebpf_operation_resolve_helper_request_t*>(request.data());
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_HELPER, request, reply) == EBPF_SUCCESS);

    // Set helper function multiple times.
    request.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id) + sizeof(uint32_t));
    reply.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + sizeof(uintptr_t));
    resolve_helper_request = reinterpret_cast<ebpf_operation_resolve_helper_request_t*>(request.data());
    resolve_helper_request->program_handle = program_handles[0];
    resolve_helper_request->helper_id[0] = 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_HELPER, request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_RESOLVE_MAP", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();

    std::vector<uint8_t> request(
        EBPF_OFFSET_OF(ebpf_operation_resolve_map_request_t, map_handle) + sizeof(ebpf_handle_t) * 2);
    std::vector<uint8_t> reply(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + sizeof(uintptr_t) * 2);
    auto resolve_map_request = reinterpret_cast<ebpf_operation_resolve_map_request_t*>(request.data());

    // Invalid handle.
    resolve_map_request->program_handle = ebpf_handle_invalid;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_MAP, request, reply) == EBPF_INVALID_OBJECT);

    // 1 invalid map.
    resolve_map_request->program_handle = program_handles[0];
    resolve_map_request->map_handle[0] = ebpf_handle_invalid;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_MAP, request, reply) == EBPF_INVALID_OBJECT);

    resolve_map_request->program_handle = program_handles[0];
    resolve_map_request->map_handle[0] = map_handles["BPF_MAP_TYPE_HASH"];
    resolve_map_request->map_handle[1] = ebpf_handle_invalid;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_MAP, request, reply) == EBPF_INVALID_OBJECT);

    // Reply too small.
    reply.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + sizeof(uintptr_t));
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_MAP, request, reply) == EBPF_INVALID_ARGUMENT);

    // 0 maps.
    request.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_map_request_t, map_handle));
    resolve_map_request = reinterpret_cast<ebpf_operation_resolve_map_request_t*>(request.data());
    resolve_map_request->program_handle = program_handles[0];
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_MAP, request, reply) == EBPF_INVALID_ARGUMENT);
}
#else
TEST_CASE("EBPF_OPERATION_RESOLVE_HELPER", "[execution_context][negative]")
{
    test_blocked_by_policy(EBPF_OPERATION_RESOLVE_HELPER);
}

TEST_CASE("EBPF_OPERATION_RESOLVE_MAP", "[execution_context][negative]")
{
    test_blocked_by_policy(EBPF_OPERATION_RESOLVE_MAP);
}
#endif // !defined(CONFIG_BPF_JIT_DISABLED)

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("EBPF_OPERATION_CREATE_PROGRAM", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();

    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data));
    std::vector<uint8_t> reply(sizeof(ebpf_operation_create_program_reply_t));
    auto create_program_request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request.data());
    create_program_request->program_type = _program_types[0];
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    // No name, no section offset, no filename - Should be permitted.
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_SUCCESS);

    request.resize(request.size() + 10);
    create_program_request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request.data());

    // Section name before start of valid region.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data) - 1;
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Program name before start of valid region.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data) - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Section name past end of valid region.
    create_program_request->section_name_offset = create_program_request->header.length + 1;
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Section name past end of valid region.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = create_program_request->header.length + 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    request.resize(request.size() + 1024);
    create_program_request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request.data());

    // Large file name.
    create_program_request->section_name_offset = create_program_request->header.length;
    create_program_request->program_name_offset = create_program_request->header.length;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Large section name - Permitted.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = create_program_request->header.length;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_SUCCESS);

    // Large program name.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);
}
#else
TEST_CASE("EBPF_OPERATION_CREATE_PROGRAM", "[execution_context][negative]")
{
    test_blocked_by_policy(EBPF_OPERATION_CREATE_PROGRAM);
}
#endif // !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)

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

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("EBPF_OPERATION_LOAD_CODE", "[execution_context][negative]")
{

    // Test with type jit.
    {
        NEGATIVE_TEST_PROLOG();

        ebpf_operation_load_code_request_t load_code_request{
            {sizeof(ebpf_operation_load_code_request_t), EBPF_OPERATION_LOAD_CODE},
            program_handles[0],
            EBPF_CODE_JIT,
            static_cast<uint8_t>('0xcc')};

        // Invalid handle.
        load_code_request.program_handle = ebpf_handle_invalid;
        REQUIRE(invoke_protocol(EBPF_OPERATION_LOAD_CODE, load_code_request) == EBPF_INVALID_OBJECT);
        load_code_request.program_handle = program_handles[0];

        load_code_request.code_type = EBPF_CODE_NATIVE;
        REQUIRE(invoke_protocol(EBPF_OPERATION_LOAD_CODE, load_code_request) == EBPF_INVALID_ARGUMENT);
        load_code_request.code_type = EBPF_CODE_JIT;

        load_code_request.code_type = static_cast<ebpf_code_type_t>(-1);
        REQUIRE(invoke_protocol(EBPF_OPERATION_LOAD_CODE, load_code_request) == EBPF_INVALID_ARGUMENT);
        load_code_request.code_type = EBPF_CODE_JIT;
    }

    // HVCI can only be changed at init time.
    _ebpf_platform_code_integrity_enabled = true;
    {
        NEGATIVE_TEST_PROLOG();

        ebpf_operation_load_code_request_t load_code_request{
            {sizeof(ebpf_operation_load_code_request_t), EBPF_OPERATION_LOAD_CODE},
            program_handles[0],
            EBPF_CODE_JIT,
            static_cast<uint8_t>('0xcc')};

        // HVCI on.
        REQUIRE(invoke_protocol(EBPF_OPERATION_LOAD_CODE, load_code_request) == EBPF_BLOCKED_BY_POLICY);
    }
    _ebpf_platform_code_integrity_enabled = false;
}
#else
TEST_CASE("EBPF_OPERATION_LOAD_CODE", "[execution_context][negative]")
{
    test_blocked_by_policy(EBPF_OPERATION_LOAD_CODE);
}
#endif // !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)

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

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("EBPF_OPERATION_GET_EC_FUNCTION", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_get_ec_function_request_t request;
    ebpf_operation_get_ec_function_reply_t reply;

    request.function = static_cast<ebpf_ec_function_t>(EBPF_EC_FUNCTION_LOG + 1);
    // Wrong EC function.
    REQUIRE(invoke_protocol(EBPF_OPERATION_GET_EC_FUNCTION, request, reply) == EBPF_INVALID_ARGUMENT);
}
#else
TEST_CASE("EBPF_OPERATION_GET_EC_FUNCTION", "[execution_context][negative]")
{
    test_blocked_by_policy(EBPF_OPERATION_GET_EC_FUNCTION);
}
#endif

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

TEST_CASE("EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER", "[execution_context][ring_buffer][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_ring_buffer_map_query_buffer_request_t request;
    ebpf_operation_ring_buffer_map_query_buffer_reply_t reply;

    request.map_handle = ebpf_handle_invalid - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER, request, reply) == EBPF_INVALID_OBJECT);

    request.map_handle = map_handles.begin()->second;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER, request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY", "[execution_context][ring_buffer][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_ring_buffer_map_async_query_request_t request;
    ebpf_operation_ring_buffer_map_async_query_reply_t reply;
    int async = 1;

    request.map_handle = ebpf_handle_invalid - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY, request, reply, &async) == EBPF_INVALID_OBJECT);

    request.map_handle = map_handles["BPF_MAP_TYPE_HASH"];
    REQUIRE(
        invoke_protocol(EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY, request, reply, &async) == EBPF_INVALID_ARGUMENT);
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
