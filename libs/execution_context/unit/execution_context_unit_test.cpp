// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "ebpf_async.h"
#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_ring_buffer.h"
#include "helpers.h"

#include <optional>
#include <set>

#define PAGE_SIZE 4096

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
    _ebpf_core_initializer() { REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS); }
    ~_ebpf_core_initializer() { ebpf_core_terminate(); }
};

template <typename T> class ebpf_object_deleter
{
  public:
    void
    operator()(T* object)
    {
        ebpf_object_release_reference(reinterpret_cast<ebpf_core_object_t*>(object));
    }
};

typedef std::unique_ptr<ebpf_map_t, ebpf_object_deleter<ebpf_map_t>> map_ptr;
typedef std::unique_ptr<ebpf_program_t, ebpf_object_deleter<ebpf_program_t>> program_ptr;
typedef std::unique_ptr<ebpf_link_t, ebpf_object_deleter<ebpf_link_t>> link_ptr;

static void
_test_crud_operations(ebpf_map_type_t map_type)
{
    _ebpf_core_initializer core;
    bool is_array;
    bool supports_find_and_delete;
    bool replace_on_full;
    bool run_at_dpc;
    ebpf_result_t error_on_full;
    switch (map_type) {
    case BPF_MAP_TYPE_HASH:
        is_array = false;
        supports_find_and_delete = true;
        replace_on_full = false;
        run_at_dpc = false;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    case BPF_MAP_TYPE_ARRAY:
        is_array = true;
        supports_find_and_delete = false;
        replace_on_full = false;
        run_at_dpc = false;
        error_on_full = EBPF_INVALID_ARGUMENT;
        break;
    case BPF_MAP_TYPE_PERCPU_HASH:
        is_array = false;
        supports_find_and_delete = true;
        replace_on_full = false;
        run_at_dpc = true;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        is_array = true;
        supports_find_and_delete = false;
        replace_on_full = false;
        run_at_dpc = false;
        error_on_full = EBPF_INVALID_ARGUMENT;
        break;
    case BPF_MAP_TYPE_LRU_HASH:
        is_array = false;
        supports_find_and_delete = true;
        replace_on_full = true;
        run_at_dpc = false;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    case BPF_MAP_TYPE_LRU_PERCPU_HASH:
        is_array = false;
        supports_find_and_delete = true;
        replace_on_full = true;
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

    ebpf_map_definition_in_memory_t map_definition{map_type, sizeof(uint32_t), sizeof(uint64_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        ebpf_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    std::vector<uint8_t> value(ebpf_map_get_definition(map.get())->value_size);
    for (uint32_t key = 0; key < 10; key++) {
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
    uint32_t bad_key = 10;
    *reinterpret_cast<uint64_t*>(value.data()) = static_cast<uint64_t>(bad_key) * static_cast<uint64_t>(bad_key);
    REQUIRE(
        ebpf_map_update_entry(
            map.get(),
            sizeof(bad_key),
            reinterpret_cast<const uint8_t*>(&bad_key),
            value.size(),
            value.data(),
            EBPF_ANY,
            0) == (replace_on_full ? EBPF_SUCCESS : error_on_full));

    if (!replace_on_full) {
        ebpf_result_t expected_result = is_array ? EBPF_INVALID_ARGUMENT : EBPF_KEY_NOT_FOUND;
        REQUIRE(
            ebpf_map_delete_entry(map.get(), sizeof(bad_key), reinterpret_cast<const uint8_t*>(&bad_key), 0) ==
            expected_result);
    }

    for (uint32_t key = 0; key < 10; key++) {
        ebpf_result_t expected_result;
        if (replace_on_full) {
            expected_result = key == 0 ? EBPF_OBJECT_NOT_FOUND : EBPF_SUCCESS;
        } else {
            expected_result = key == 10 ? EBPF_OBJECT_NOT_FOUND : EBPF_SUCCESS;
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
    for (uint32_t key = 0; key < 10; key++) {
        REQUIRE(
            ebpf_map_next_key(
                map.get(),
                sizeof(key),
                key == 0 ? nullptr : reinterpret_cast<const uint8_t*>(&previous_key),
                reinterpret_cast<uint8_t*>(&next_key)) == EBPF_SUCCESS);

        previous_key = next_key;
        keys.insert(previous_key);
    }
    REQUIRE(keys.size() == 10);
    REQUIRE(
        ebpf_map_next_key(
            map.get(),
            sizeof(previous_key),
            reinterpret_cast<const uint8_t*>(&previous_key),
            reinterpret_cast<uint8_t*>(&next_key)) == EBPF_NO_MORE_KEYS);

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
                EPBF_MAP_FIND_FLAG_DELETE) == EBPF_SUCCESS);

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
                EPBF_MAP_FIND_FLAG_DELETE) == EBPF_INVALID_ARGUMENT);
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

TEST_CASE("map_crud_operations_lpm_trie_32", "[execution_context]")
{
    _ebpf_core_initializer core;
    const size_t max_string = 16;
    typedef struct _lpm_trie_key
    {
        uint32_t prefix_length;
        uint8_t value[4];
    } lpm_trie_key_t;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_LPM_TRIE, sizeof(lpm_trie_key_t), max_string, 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        ebpf_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    std::vector<std::pair<lpm_trie_key_t, const char*>> keys{
        {{24, 192, 168, 15, 0}, "192.168.15.0/24"},
        {{24, 192, 168, 16, 0}, "192.168.16.0/24"},
        {{31, 192, 168, 14, 0}, "192.168.14.0/31"},
        {{30, 192, 168, 14, 0}, "192.168.14.0/30"},
        {{29, 192, 168, 14, 0}, "192.168.14.0/29"},
        {{16, 192, 168, 0, 0}, "192.168.0.0/16"},
        {{16, 10, 10, 0, 0}, "10.0.0.0/16"},
        {{8, 10, 0, 0, 0}, "10.0.0.0/8"},
        {{0, 0, 0, 0, 0}, "0.0.0.0/0"},
    };

    std::vector<std::pair<lpm_trie_key_t, std::string>> tests{
        {{32, 192, 168, 15, 1}, "192.168.15.0/24"},
        {{32, 192, 168, 16, 25}, "192.168.16.0/24"},
        {{32, 192, 168, 14, 1}, "192.168.14.0/31"},
        {{32, 192, 168, 14, 2}, "192.168.14.0/30"},
        {{32, 192, 168, 14, 4}, "192.168.14.0/29"},
        {{32, 192, 168, 14, 9}, "192.168.0.0/16"},
        {{32, 10, 10, 10, 10}, "10.0.0.0/16"},
        {{32, 10, 11, 10, 10}, "10.0.0.0/8"},
        {{32, 11, 0, 0, 0}, "0.0.0.0/0"},
    };

    for (auto& [key, value] : keys) {
        std::string local_value = value;
        local_value.resize(max_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(local_value.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    for (auto& [key, result] : tests) {
        char* value = nullptr;
        REQUIRE(
            ebpf_map_find_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<uint8_t*>(&value),
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
        REQUIRE(std::string(value) == result);
    }
}

void
generate_prefix(size_t length, uint8_t value, uint8_t prefix[16])
{
    size_t index = 0;
    memset(prefix, 0, sizeof(prefix));
    for (index = 0; index < length / 8; index++) {
        prefix[index] = value;
    }
    prefix[index] = value << (8 - (length % 8));
}

TEST_CASE("map_crud_operations_lpm_trie_128", "[execution_context]")
{
    _ebpf_core_initializer core;

    const size_t max_string = 20;
    typedef struct _lpm_trie_key
    {
        uint32_t prefix_length;
        uint8_t value[16];
    } lpm_trie_key_t;

    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_LPM_TRIE, sizeof(lpm_trie_key_t), max_string, 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        ebpf_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    std::vector<std::pair<lpm_trie_key_t, const char*>> keys{
        {{96}, "CC/96"},
        {{96}, "CD/96"},
        {{124}, "DD/124"},
        {{120}, "DD/120"},
        {{116}, "DD/116"},
        {{64}, "AA/64"},
        {{64}, "BB/64"},
        {{32}, "BB/32"},
        {{0}, "/0"},
    };
    {
        std::vector<uint8_t> values{
            0xCC,
            0xCD,
            0xDD,
            0xDD,
            0xDD,
            0xAA,
            0xBB,
            0xBB,
        };
        for (size_t index = 0; index < values.size(); index++) {
            generate_prefix(keys[index].first.prefix_length, values[index], keys[index].first.value);
        }
    }
    std::vector<std::pair<lpm_trie_key_t, std::string>> tests{
        {{96}, "CC/96"},
        {{96}, "CD/96"},
        {{124}, "DD/124"},
        {{120}, "DD/120"},
        {{116}, "DD/116"},
        {{64}, "AA/64"},
        {{64}, "BB/64"},
        {{32}, "BB/32"},
        {{128}, "/0"},
    };
    {
        std::vector<uint8_t> values{
            0xCC,
            0xCD,
            0xDD,
            0xDD,
            0xDD,
            0xAA,
            0xBB,
            0xBB,
            0xFF,
        };
        for (size_t index = 0; index < values.size(); index++) {
            generate_prefix(tests[index].first.prefix_length, values[index], tests[index].first.value);
        }
    }

    for (auto& [key, value] : keys) {
        std::string local_value = value;
        local_value.resize(max_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(local_value.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    for (auto& [key, result] : tests) {
        char* value = nullptr;
        REQUIRE(
            ebpf_map_find_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<uint8_t*>(&value),
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
        REQUIRE(std::string(value) == result);
    }
}

TEST_CASE("map_crud_operations_queue", "[execution_context]")
{
    _ebpf_core_initializer core;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_QUEUE, 0, sizeof(uint32_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        ebpf_utf8_string_t map_name = {0};
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
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_STACK, 0, sizeof(uint32_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        ebpf_utf8_string_t map_name = {0};
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

TEST_CASE("program", "[execution_context]")
{
    _ebpf_core_initializer core;

    program_ptr program;
    {
        ebpf_program_t* local_program = nullptr;
        REQUIRE(ebpf_program_create(&local_program) == EBPF_SUCCESS);
        program.reset(local_program);
    }

    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint64_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        ebpf_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    const ebpf_utf8_string_t program_name{(uint8_t*)("foo"), 3};
    const ebpf_utf8_string_t section_name{(uint8_t*)("bar"), 3};
    program_info_provider_t program_info_provider(EBPF_PROGRAM_TYPE_XDP);

    const ebpf_program_parameters_t program_parameters{
        EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP, program_name, section_name};
    ebpf_program_info_t* program_info;

    REQUIRE(ebpf_program_initialize(program.get(), &program_parameters) == EBPF_SUCCESS);

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
        EBPF_COUNT_OF(helper_functions), (uint64_t*)helper_functions};

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
    bind_md_t ctx{0};
    ebpf_execution_context_state_t state{};
    ebpf_get_execution_context_state(&state);
    ebpf_program_invoke(program.get(), &ctx, &result, &state);
    REQUIRE(result == TEST_FUNCTION_RETURN);

    std::vector<uint8_t> input_buffer(10);
    std::vector<uint8_t> output_buffer(10);
    ebpf_program_test_run_options_t options = {0};
    options.data_in = input_buffer.data();
    options.data_size_in = input_buffer.size();
    options.data_out = output_buffer.data();
    options.data_size_out = output_buffer.size();
    options.repeat_count = 10;

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

    uint64_t addresses[TOTAL_HELPER_COUNT] = {};
    uint32_t helper_function_ids[] = {1, 3, 2};
    REQUIRE(
        ebpf_program_set_helper_function_ids(program.get(), EBPF_COUNT_OF(helper_function_ids), helper_function_ids) ==
        EBPF_SUCCESS);
    REQUIRE(
        ebpf_program_get_helper_function_addresses(program.get(), EBPF_COUNT_OF(helper_function_ids), addresses) ==
        EBPF_SUCCESS);
    REQUIRE(addresses[0] != 0);
    REQUIRE(addresses[1] != 0);
    REQUIRE(addresses[2] != 0);

    link_ptr link;
    {
        ebpf_link_t* local_link = nullptr;
        REQUIRE(ebpf_link_create(&local_link) == EBPF_SUCCESS);
        link.reset(local_link);
    }

    REQUIRE(ebpf_link_initialize(link.get(), EBPF_ATTACH_TYPE_XDP, nullptr, 0) == EBPF_SUCCESS);

    // Correct attach type, but wrong program type.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_XDP);

        REQUIRE(ebpf_link_attach_program(link.get(), program.get()) == EBPF_EXTENSION_FAILED_TO_LOAD);
    }

    // Wrong attach type, but correct program type.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_BIND);

        REQUIRE(ebpf_link_attach_program(link.get(), program.get()) == EBPF_EXTENSION_FAILED_TO_LOAD);
    }

    // Correct attach type and correct program type.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);

        // First attach should succeed.
        REQUIRE(ebpf_link_attach_program(link.get(), program.get()) == EBPF_SUCCESS);

        // Second attach should fail.
        REQUIRE(ebpf_link_attach_program(link.get(), program.get()) == EBPF_INVALID_ARGUMENT);

        // First detach should succeed.
        ebpf_link_detach_program(link.get());

        // Second detach should be no-op.
        ebpf_link_detach_program(link.get());
    }

    link.reset();

    ebpf_free_trampoline_table(table.release());
}

TEST_CASE("name size", "[execution_context]")
{
    _ebpf_core_initializer core;
    program_info_provider_t program_info_provider(EBPF_PROGRAM_TYPE_BIND);

    program_ptr program;
    {
        ebpf_program_t* local_program = nullptr;
        REQUIRE(ebpf_program_create(&local_program) == EBPF_SUCCESS);
        program.reset(local_program);
    }
    const ebpf_utf8_string_t oversize_name{
        (uint8_t*)("a234567890123456789012345678901234567890123456789012345678901234"), 64};
    const ebpf_utf8_string_t section_name{(uint8_t*)("bar"), 3};
    const ebpf_program_parameters_t program_parameters{
        EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND, oversize_name, section_name};

    REQUIRE(ebpf_program_initialize(program.get(), &program_parameters) == EBPF_INVALID_ARGUMENT);

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

TEST_CASE("ring_buffer_async_query", "[execution_context]")
{
    _ebpf_core_initializer core;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_RINGBUF, 0, 0, 64 * 1024};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        ebpf_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    struct _completion
    {
        uint8_t* buffer;
        ebpf_ring_buffer_map_async_query_result_t async_query_result = {};
        uint64_t value;
    } completion;

    REQUIRE(ebpf_ring_buffer_map_query_buffer(map.get(), &completion.buffer) == EBPF_SUCCESS);

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
            {reinterpret_cast<uint8_t*>(name.data()), name.size()},
            {reinterpret_cast<uint8_t*>(name.data()), name.size()},
            EBPF_CODE_NONE};
        ebpf_handle_t handle;
        REQUIRE(ebpf_program_create_and_initialize(&params, &handle) == EBPF_SUCCESS);
        program_handles.push_back(handle);
    }
    for (const auto& [name, def] : _map_definitions) {
        ebpf_utf8_string_t utf8_name{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())), name.size()};
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

#define NEGATIVE_TEST_PROLOG()                                                            \
    _ebpf_core_initializer core;                                                          \
    std::vector<std::unique_ptr<_program_info_provider>> program_info_providers;          \
    for (const auto& type : _program_types) {                                             \
        program_info_providers.push_back(std::make_unique<_program_info_provider>(type)); \
    }                                                                                     \
    std::vector<ebpf_handle_t> program_handles;                                           \
    std::map<std::string, ebpf_handle_t> map_handles;                                     \
    create_various_objects(program_handles, map_handles);

// These tests exist to verify ebpf_core's parsing of messages.
// See libbpf_test.cpp for invalid parameter but correctly formed message cases.
TEST_CASE("EBPF_OPERATION_RESOLVE_HELPER", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();

    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id) + sizeof(uint32_t));
    std::vector<uint8_t> reply(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + sizeof(uintptr_t));
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

TEST_CASE("EBPF_OPERATION_GET_EC_FUNCTION", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_get_ec_function_request_t request;
    ebpf_operation_get_ec_function_reply_t reply;

    request.function = static_cast<ebpf_ec_function_t>(EBPF_EC_FUNCTION_LOG + 1);
    // Wrong EC function.
    REQUIRE(invoke_protocol(EBPF_OPERATION_GET_EC_FUNCTION, request, reply) == EBPF_INVALID_ARGUMENT);
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
    REQUIRE(invoke_protocol(EBPF_OPERATION_GET_PROGRAM_INFO, request, reply) == EBPF_EXTENSION_FAILED_TO_LOAD);

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

TEST_CASE("EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_ring_buffer_map_query_buffer_request_t request;
    ebpf_operation_ring_buffer_map_query_buffer_reply_t reply;

    request.map_handle = ebpf_handle_invalid - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER, request, reply) == EBPF_INVALID_OBJECT);

    request.map_handle = map_handles.begin()->second;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER, request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY", "[execution_context][negative]")
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

// TODO: Add more native module loading IOCTL negative tests.
// https://github.com/microsoft/ebpf-for-windows/issues/1139
// EBPF_OPERATION_LOAD_NATIVE_MODULE
// EBPF_OPERATION_LOAD_NATIVE_PROGRAMS
