// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

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

void
test_crud_operations(ebpf_map_type_t map_type)
{
    _ebpf_core_initializer core;

    ebpf_map_definition_t map_definition{
        sizeof(ebpf_map_definition_t), map_type, sizeof(uint32_t), sizeof(uint64_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        REQUIRE(ebpf_map_create(&map_definition, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    for (uint32_t key = 0; key < 10; key++) {
        uint64_t value = static_cast<uint64_t>(key) * static_cast<uint64_t>(key);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(), reinterpret_cast<const uint8_t*>(&key), reinterpret_cast<const uint8_t*>(&value)) ==
            EBPF_SUCCESS);
    }

    // Test for inserting max_entries + 1
    uint32_t bad_key = 11;
    uint64_t bad_value = 11 * 11;
    REQUIRE(
        ebpf_map_update_entry(
            map.get(), reinterpret_cast<const uint8_t*>(&bad_key), reinterpret_cast<const uint8_t*>(&bad_value)) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(ebpf_map_delete_entry(map.get(), reinterpret_cast<const uint8_t*>(&bad_key)) == EBPF_KEY_NOT_FOUND);

    for (uint32_t key = 0; key < 10; key++) {
        uint64_t* value =
            reinterpret_cast<uint64_t*>(ebpf_map_find_entry(map.get(), reinterpret_cast<const uint8_t*>(&key)));

        REQUIRE(value != nullptr);
        REQUIRE(*value == key * key);
    }

    uint32_t previous_key;
    uint32_t next_key;
    for (uint32_t key = 0; key < 10; key++) {
        REQUIRE(
            ebpf_map_next_key(
                map.get(),
                key == 0 ? nullptr : reinterpret_cast<const uint8_t*>(&previous_key),
                reinterpret_cast<uint8_t*>(&next_key)) == EBPF_SUCCESS);

        previous_key = next_key;
        REQUIRE(previous_key == key);
    }
    REQUIRE(
        ebpf_map_next_key(
            map.get(), reinterpret_cast<const uint8_t*>(&previous_key), reinterpret_cast<uint8_t*>(&next_key)) ==
        EBPF_NO_MORE_KEYS);

    for (uint32_t key = 0; key < 10; key++) {
        REQUIRE(ebpf_map_delete_entry(map.get(), reinterpret_cast<const uint8_t*>(&key)) == EBPF_SUCCESS);
    }

    auto retrieved_map_definition = ebpf_map_get_definition(map.get());
    REQUIRE(retrieved_map_definition != nullptr);
    REQUIRE(memcmp(retrieved_map_definition, &map_definition, sizeof(map_definition)) == 0);
}

TEST_CASE("map_crud_operations_array", "[execution_context]") { test_crud_operations(EBPF_MAP_TYPE_ARRAY); }

TEST_CASE("map_crud_operations_hash", "[execution_context]") { test_crud_operations(EBPF_MAP_TYPE_HASH); }

#define TEST_FUNCTION_RETURN 42

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

    ebpf_map_definition_t map_definition{
        sizeof(ebpf_map_definition_t), EBPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint64_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        REQUIRE(ebpf_map_create(&map_definition, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    const ebpf_utf8_string_t program_name{(uint8_t*)("foo"), 3};
    const ebpf_utf8_string_t section_name{(uint8_t*)("bar"), 3};
    program_info_provider_t program_info_provider(EBPF_PROGRAM_TYPE_BIND);

    const ebpf_program_parameters_t program_parameters{EBPF_PROGRAM_TYPE_BIND, program_name, section_name};
    ebpf_program_parameters_t returned_program_parameters{};
    ebpf_program_info_t* program_info;

    REQUIRE(ebpf_program_initialize(program.get(), &program_parameters) == EBPF_SUCCESS);

    REQUIRE(ebpf_program_get_properties(program.get(), &returned_program_parameters) == EBPF_SUCCESS);
    REQUIRE(
        memcmp(
            &program_parameters.program_type,
            &returned_program_parameters.program_type,
            sizeof(program_parameters.program_type)) == 0);

    REQUIRE(ebpf_program_get_program_info_data(program.get(), &program_info) == EBPF_SUCCESS);
    REQUIRE(program_info != nullptr);
    ebpf_program_free_program_info_data(program_info);

    ebpf_map_t* maps[] = {map.get()};

    REQUIRE(((ebpf_object_t*)map.get())->reference_count == 1);
    REQUIRE(ebpf_program_associate_maps(program.get(), maps, EBPF_COUNT_OF(maps)) == EBPF_SUCCESS);
    REQUIRE(((ebpf_object_t*)map.get())->reference_count == 2);

    ebpf_trampoline_table_t* table = NULL;
    ebpf_result_t (*test_function)();
    auto provider_function1 = []() { return (ebpf_result_t)TEST_FUNCTION_RETURN; };
    ebpf_result_t (*function_pointer1)() = provider_function1;
    const void* helper_functions[] = {(void*)function_pointer1};
    ebpf_helper_function_addresses_t helper_function_addresses = {EBPF_COUNT_OF(helper_functions),
                                                                  (uint64_t*)helper_functions};

    REQUIRE(ebpf_allocate_trampoline_table(1, &table) == EBPF_SUCCESS);
    REQUIRE(ebpf_update_trampoline_table(table, &helper_function_addresses) == EBPF_SUCCESS);
    REQUIRE(ebpf_get_trampoline_function(table, 0, reinterpret_cast<void**>(&test_function)) == EBPF_SUCCESS);

    // Size of the actual function is unknown, but we know the allocation is on page granularity.
    REQUIRE(
        ebpf_program_load_machine_code(program.get(), reinterpret_cast<uint8_t*>(test_function), PAGE_SIZE) ==
        EBPF_SUCCESS);
    uint32_t result = 0;
    bind_md_t ctx{0};
    ebpf_program_invoke(program.get(), &ctx, &result);
    REQUIRE(result == TEST_FUNCTION_RETURN);

    uint64_t address = 0;
    REQUIRE(ebpf_program_get_helper_function_address(program.get(), 1, &address) == EBPF_SUCCESS);
    REQUIRE(address != 0);
    REQUIRE(ebpf_program_get_helper_function_address(program.get(), 0, &address) == EBPF_SUCCESS);
    REQUIRE(address == 0);
    REQUIRE(ebpf_program_get_helper_function_address(program.get(), 0xFFFF, &address) == EBPF_INVALID_ARGUMENT);
    REQUIRE(address == 0);
    ebpf_free_trampoline_table(table);
}
