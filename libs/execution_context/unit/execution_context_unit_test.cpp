// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <set>

#include <optional>
#include "catch_wrapper.hpp"
#include "ebpf_async.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "helpers.h"

#define PAGE_SIZE 4096

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
        ebpf_object_release_reference(reinterpret_cast<ebpf_object_t*>(object));
    }
};

typedef std::unique_ptr<ebpf_map_t, ebpf_object_deleter<ebpf_map_t>> map_ptr;
typedef std::unique_ptr<ebpf_program_t, ebpf_object_deleter<ebpf_program_t>> program_ptr;

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

    ebpf_map_definition_in_memory_t map_definition{
        sizeof(ebpf_map_definition_in_memory_t), map_type, sizeof(uint32_t), sizeof(uint64_t), 10};
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

    // Test for inserting max_entries + 1
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

    typedef struct _lpm_trie_key
    {
        uint32_t prefix_length;
        uint8_t value[4];
    } lpm_trie_key_t;
    ebpf_map_definition_in_memory_t map_definition{
        sizeof(ebpf_map_definition_in_memory_t), BPF_MAP_TYPE_LPM_TRIE, sizeof(lpm_trie_key_t), 16, 10};
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
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(value),
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

    typedef struct _lpm_trie_key
    {
        uint32_t prefix_length;
        uint8_t value[16];
    } lpm_trie_key_t;

    ebpf_map_definition_in_memory_t map_definition{
        sizeof(ebpf_map_definition_in_memory_t), BPF_MAP_TYPE_LPM_TRIE, sizeof(lpm_trie_key_t), 20, 10};
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
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(value),
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
    ebpf_map_definition_in_memory_t map_definition{
        sizeof(ebpf_map_definition_in_memory_t), BPF_MAP_TYPE_QUEUE, 0, sizeof(uint32_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        ebpf_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    for (uint32_t value = 0; value < 9; value++) {
        REQUIRE(
            ebpf_map_update_entry(map.get(), 0, NULL, sizeof(value), reinterpret_cast<uint8_t*>(&value), EBPF_ANY, 0) ==
            EBPF_SUCCESS);
    }
    uint32_t extra_value = 10;
    REQUIRE(
        ebpf_map_update_entry(
            map.get(), 0, NULL, sizeof(extra_value), reinterpret_cast<uint8_t*>(&extra_value), EBPF_ANY, 0) ==
        EBPF_OUT_OF_SPACE);

    // Peek the first element.
    uint32_t return_value = MAXUINT32;
    REQUIRE(
        ebpf_map_find_entry(map.get(), 0, NULL, sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_SUCCESS);

    REQUIRE(return_value == 0);

    for (uint32_t value = 0; value < 9; value++) {
        REQUIRE(
            ebpf_map_find_entry(
                map.get(),
                0,
                NULL,
                sizeof(return_value),
                reinterpret_cast<uint8_t*>(&return_value),
                EPBF_MAP_FIND_FLAG_DELETE) == EBPF_SUCCESS);
        REQUIRE(return_value == value);
    }

    REQUIRE(
        ebpf_map_find_entry(map.get(), 0, NULL, sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_OBJECT_NOT_FOUND);
}

TEST_CASE("map_crud_operations_stack", "[execution_context]")
{
    _ebpf_core_initializer core;
    ebpf_map_definition_in_memory_t map_definition{
        sizeof(ebpf_map_definition_in_memory_t), BPF_MAP_TYPE_STACK, 0, sizeof(uint32_t), 10};
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
        ebpf_map_find_entry(map.get(), 0, NULL, sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_OBJECT_NOT_FOUND);

    for (uint32_t value = 0; value < 10; value++) {
        REQUIRE(
            ebpf_map_update_entry(map.get(), 0, NULL, sizeof(value), reinterpret_cast<uint8_t*>(&value), EBPF_ANY, 0) ==
            EBPF_SUCCESS);
    }
    uint32_t extra_value = 10;
    REQUIRE(
        ebpf_map_update_entry(
            map.get(), 0, NULL, sizeof(extra_value), reinterpret_cast<uint8_t*>(&extra_value), EBPF_ANY, 0) ==
        EBPF_OUT_OF_SPACE);

    // Peek the first element.
    REQUIRE(
        ebpf_map_find_entry(map.get(), 0, NULL, sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
        EBPF_SUCCESS);

    REQUIRE(return_value == 9);

    for (uint32_t value = 0; value < 10; value++) {
        REQUIRE(
            ebpf_map_find_entry(
                map.get(),
                0,
                NULL,
                sizeof(return_value),
                reinterpret_cast<uint8_t*>(&return_value),
                EPBF_MAP_FIND_FLAG_DELETE) == EBPF_SUCCESS);
        REQUIRE(return_value == 9 - value);
    }

    REQUIRE(
        ebpf_map_find_entry(map.get(), 0, NULL, sizeof(return_value), reinterpret_cast<uint8_t*>(&return_value), 0) ==
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

    ebpf_map_definition_in_memory_t map_definition{
        sizeof(ebpf_map_definition_in_memory_t), BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint64_t), 10};
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
    program_info_provider_t program_info_provider(EBPF_PROGRAM_TYPE_BIND);

    const ebpf_program_parameters_t program_parameters{EBPF_PROGRAM_TYPE_BIND, program_name, section_name};
    ebpf_program_info_t* program_info;

    REQUIRE(ebpf_program_initialize(program.get(), &program_parameters) == EBPF_SUCCESS);

    const ebpf_program_type_t* returned_program_type = ebpf_program_type(program.get());
    REQUIRE(
        memcmp(&program_parameters.program_type, returned_program_type, sizeof(program_parameters.program_type)) == 0);

    REQUIRE(ebpf_program_get_program_info(program.get(), &program_info) == EBPF_SUCCESS);
    REQUIRE(program_info != nullptr);
    ebpf_program_free_program_info(program_info);

    ebpf_map_t* maps[] = {map.get()};

    REQUIRE(((ebpf_object_t*)map.get())->reference_count == 1);
    REQUIRE(ebpf_program_associate_maps(program.get(), maps, EBPF_COUNT_OF(maps)) == EBPF_SUCCESS);
    REQUIRE(((ebpf_object_t*)map.get())->reference_count == 2);

    ebpf_trampoline_table_t* table = NULL;
    ebpf_result_t (*test_function)();
    auto provider_function1 = []() { return (ebpf_result_t)TEST_FUNCTION_RETURN; };
    ebpf_result_t (*function_pointer1)() = provider_function1;
    uint32_t test_function_ids[] = {(EBPF_MAX_GENERAL_HELPER_FUNCTION + 1)};
    const void* helper_functions[] = {(void*)function_pointer1};
    ebpf_helper_function_addresses_t helper_function_addresses = {
        EBPF_COUNT_OF(helper_functions), (uint64_t*)helper_functions};

    REQUIRE(ebpf_allocate_trampoline_table(1, &table) == EBPF_SUCCESS);
    REQUIRE(
        ebpf_update_trampoline_table(
            table, EBPF_COUNT_OF(test_function_ids), test_function_ids, &helper_function_addresses) == EBPF_SUCCESS);
    REQUIRE(ebpf_get_trampoline_function(table, 0, reinterpret_cast<void**>(&test_function)) == EBPF_SUCCESS);

    // Size of the actual function is unknown, but we know the allocation is on page granularity.
    REQUIRE(
        ebpf_program_load_code(program.get(), EBPF_CODE_NATIVE, reinterpret_cast<uint8_t*>(test_function), PAGE_SIZE) ==
        EBPF_SUCCESS);
    uint32_t result = 0;
    bind_md_t ctx{0};
    ebpf_program_invoke(program.get(), &ctx, &result);
    REQUIRE(result == TEST_FUNCTION_RETURN);

    uint64_t addresses[TOTAL_HELPER_COUNT] = {};
    uint32_t helper_function_ids[] = {1, 0, 2};
    REQUIRE(
        ebpf_program_set_helper_function_ids(program.get(), EBPF_COUNT_OF(helper_function_ids), helper_function_ids) ==
        EBPF_SUCCESS);
    REQUIRE(
        ebpf_program_get_helper_function_addresses(program.get(), EBPF_COUNT_OF(helper_function_ids), addresses) ==
        EBPF_SUCCESS);
    REQUIRE(addresses[0] != 0);
    REQUIRE(addresses[1] == 0);
    REQUIRE(addresses[2] != 0);
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
    const ebpf_program_parameters_t program_parameters{EBPF_PROGRAM_TYPE_BIND, oversize_name, section_name};

    REQUIRE(ebpf_program_initialize(program.get(), &program_parameters) == EBPF_INVALID_ARGUMENT);

    ebpf_map_definition_in_memory_t map_definition{
        sizeof(ebpf_map_definition_in_memory_t), BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint64_t), 10};
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
    ebpf_map_definition_in_memory_t map_definition{
        sizeof(ebpf_map_definition_in_memory_t), BPF_MAP_TYPE_RINGBUF, 0, 0, 64 * 1024};
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
            &completion, [](void* context, size_t output_buffer_length, ebpf_result_t result) {
                UNREFERENCED_PARAMETER(output_buffer_length);
                auto completion = reinterpret_cast<_completion*>(context);
                auto async_query_result = &completion->async_query_result;
                auto record = ebpf_ring_buffer_next_record(
                    completion->buffer, sizeof(uint64_t), async_query_result->consumer, async_query_result->producer);
                completion->value = *(uint64_t*)(record->data);
                REQUIRE(result == EBPF_SUCCESS);
            }) == EBPF_SUCCESS);

    REQUIRE(ebpf_ring_buffer_map_async_query(map.get(), &completion.async_query_result, &completion) == EBPF_PENDING);

    uint64_t value = 1;
    REQUIRE(ebpf_ring_buffer_map_output(map.get(), reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);

    REQUIRE(completion.value == value);
}