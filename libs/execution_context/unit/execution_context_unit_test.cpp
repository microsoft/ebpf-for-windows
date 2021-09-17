// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <set>

#include "catch_wrapper.hpp"
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
_test_crud_operations(ebpf_map_type_t map_type, bool is_array, bool replace_on_full = false)
{
    _ebpf_core_initializer core;

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
            0) == (replace_on_full ? EBPF_SUCCESS : EBPF_INVALID_ARGUMENT));

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

    auto retrieved_map_definition = *ebpf_map_get_definition(map.get());
    retrieved_map_definition.value_size = ebpf_map_get_effective_value_size(map.get());
    REQUIRE(memcmp(&retrieved_map_definition, &map_definition, sizeof(map_definition)) == 0);
}

TEST_CASE("map_crud_operations_array", "[execution_context]") { _test_crud_operations(BPF_MAP_TYPE_ARRAY, true); }

TEST_CASE("map_crud_operations_hash", "[execution_context]") { _test_crud_operations(BPF_MAP_TYPE_HASH, false); }

TEST_CASE("map_crud_operations_lru_hash", "[execution_context]")
{
    _test_crud_operations(BPF_MAP_TYPE_LRU_HASH, false, true);
}

TEST_CASE("map_crud_operations_array_per_cpu", "[execution_context]")
{
    emulate_dpc_t dpc(0);
    _test_crud_operations(BPF_MAP_TYPE_PERCPU_ARRAY, true);
}

TEST_CASE("map_crud_operations_hash_per_cpu", "[execution_context]")
{
    emulate_dpc_t dpc(0);
    _test_crud_operations(BPF_MAP_TYPE_PERCPU_HASH, false);
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
