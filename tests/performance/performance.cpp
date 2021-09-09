// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "catch_wrapper.hpp"
#include "ebpf.h"
#include "ebpf_epoch.h"
#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "helpers.h"
#include "libbpf.h"
#include "performance_measure.h"
#include "test_helper.hpp"
extern "C"
{
#include "ubpf.h"
}

#define PERF_TEST(FUNCTION)                                                 \
    TEST_CASE(#FUNCTION "_preemption", "[performance]") { FUNCTION(true); } \
    TEST_CASE(#FUNCTION "_no_preemption", "[performance]") { FUNCTION(false); }

static void
_perf_epoch_enter_exit()
{
    ebpf_epoch_enter();
    ebpf_epoch_exit();
}

static void
_perf_epoch_enter_alloc_free_exit()
{
    ebpf_epoch_enter();
    void* p = ebpf_epoch_allocate(10);
    ebpf_epoch_free(p);
    // Disable C6001
    // We are intentionally modifying memory after free, but relying on epoch protection.
#pragma warning(push)
#pragma warning(disable : 6001)
    memset(p, 0xAA, 10);
#pragma warning(pop)
    ebpf_epoch_exit();
}

static void
_perf_bpf_get_prandom_u32()
{
    ebpf_epoch_enter();
    ebpf_random_uint32();
    ebpf_epoch_exit();
}

static void
_perf_bpf_ktime_get_boot_ns()
{
    uint64_t time;
    ebpf_epoch_enter();
    time = ebpf_query_interrupt_time_precise() * 100;
    ebpf_epoch_exit();
}

static void
_perf_bpf_get_smp_processor_id()
{
    ebpf_epoch_enter();
    ebpf_get_current_cpu();
    ebpf_epoch_exit();
}

/**
 * @brief Helper function to set up the hash-table for testing.
 * All tests perform the operation under test multiplier() times.
 */
typedef class _ebpf_hash_table_test_state
{
  public:
    _ebpf_hash_table_test_state()
    {
        cpu_count = ebpf_get_cpu_count();
        REQUIRE(ebpf_platform_initiate() == EBPF_SUCCESS);
        platform_initiated = true;
        REQUIRE(ebpf_epoch_initiate() == EBPF_SUCCESS);
        epoch_initated = true;

        ebpf_epoch_enter();
        keys.resize(static_cast<size_t>(cpu_count) * 4ull);
        REQUIRE(
            ebpf_hash_table_create(
                &table,
                ebpf_epoch_allocate,
                ebpf_epoch_free,
                sizeof(uint32_t),
                sizeof(uint64_t),
                keys.size(),
                nullptr) == EBPF_SUCCESS);
        for (auto& key : keys) {
            uint64_t value = 12345678;
            key = ebpf_random_uint32();

            REQUIRE(
                ebpf_hash_table_update(
                    table,
                    reinterpret_cast<uint8_t*>(&key),
                    reinterpret_cast<uint8_t*>(&value),
                    EBPF_HASH_TABLE_OPERATION_ANY) == EBPF_SUCCESS);
        }
        ebpf_epoch_exit();
    }
    ~_ebpf_hash_table_test_state()
    {
        ebpf_hash_table_destroy(table);

        if (epoch_initated)
            ebpf_epoch_terminate();
        if (platform_initiated)
            ebpf_platform_terminate();
    }

    void
    test_find()
    {
        uint8_t* value;
        for (auto& key : keys) {
            ebpf_epoch_enter();
            ebpf_hash_table_find(table, reinterpret_cast<uint8_t*>(&key), &value);
            ebpf_epoch_exit();
        }
    }

    void
    test_next_key()
    {
        uint32_t next_key;
        for (auto& key : keys) {
            ebpf_epoch_enter();
            ebpf_hash_table_next_key(table, reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&next_key));
            ebpf_epoch_exit();
        }
    }

    void
    test_replace_value(uint32_t current_cpu)
    {
        uint64_t value = 12345678;
        // Update non-conflicting keys
        for (uint32_t i = 0; i < cpu_count; i++) {
            uint32_t start = current_cpu * 4;
            uint32_t end = start + 4;
            for (uint32_t index = start; index < end; index++) {
                ebpf_epoch_enter();
                ebpf_hash_table_update(
                    table,
                    reinterpret_cast<uint8_t*>(&keys[index]),
                    reinterpret_cast<uint8_t*>(&value),
                    EBPF_HASH_TABLE_OPERATION_REPLACE);
                ebpf_epoch_exit();
            }
        }
    }

    void
    test_replace_value_overlap()
    {
        uint64_t value = 12345678;
        // Update conflicting keys
        for (auto& key : keys) {
            ebpf_epoch_enter();
            ebpf_hash_table_update(
                table,
                reinterpret_cast<uint8_t*>(&key),
                reinterpret_cast<uint8_t*>(&value),
                EBPF_HASH_TABLE_OPERATION_REPLACE);
            ebpf_epoch_exit();
        }
    }

    size_t
    multiplier()
    {
        return keys.size();
    }

  private:
    ebpf_hash_table_t* table;
    std::vector<uint32_t> keys;
    bool platform_initiated = false;
    bool epoch_initated = false;
    uint32_t cpu_count;

} ebpf_hash_table_test_state_t;

typedef class _ebpf_program_test_state
{
  public:
    _ebpf_program_test_state(std::vector<ebpf_instruction_t> byte_code)
        : byte_code(byte_code), program_info_provider(EBPF_PROGRAM_TYPE_XDP)
    {
        ebpf_program_parameters_t parameters = {EBPF_PROGRAM_TYPE_XDP};
        REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
        REQUIRE(ebpf_program_create(&program) == EBPF_SUCCESS);

        REQUIRE(ebpf_program_initialize(program, &parameters) == EBPF_SUCCESS);
    }
    ~_ebpf_program_test_state()
    {
        ebpf_object_release_reference(reinterpret_cast<ebpf_object_t*>(program));
        ebpf_core_terminate();
    }

    void
    prepare_jit_program()
    {
        ubpf_vm* vm = ubpf_create();
        char* error_message = nullptr;
        std::vector<uint8_t> machine_code(1024);
        size_t machine_code_size = machine_code.size();
        REQUIRE(
            ubpf_load(
                vm,
                reinterpret_cast<uint8_t*>(byte_code.data()),
                static_cast<uint32_t>(byte_code.size() * sizeof(ebpf_instruction_t)),
                &error_message) == 0);
        REQUIRE(ubpf_translate(vm, machine_code.data(), &machine_code_size, &error_message) == 0);
        machine_code.resize(machine_code_size);
        REQUIRE(
            ebpf_program_load_code(
                program, EBPF_CODE_NATIVE, machine_code.data(), machine_code.size() * sizeof(ebpf_instruction_t)) ==
            EBPF_SUCCESS);
    }

    void
    prepare_interpret_program()
    {
        REQUIRE(
            ebpf_program_load_code(
                program,
                EBPF_CODE_EBPF,
                reinterpret_cast<uint8_t*>(byte_code.data()),
                byte_code.size() * sizeof(ebpf_instruction_t)) == EBPF_SUCCESS);
    }

    void
    test(void* context)
    {
        uint32_t result;
        ebpf_epoch_enter();
        ebpf_program_invoke(program, context, &result);
        ebpf_epoch_exit();
    }

  private:
    ebpf_program_t* program;
    std::vector<ebpf_instruction_t> byte_code;
    _program_info_provider program_info_provider;
} ebpf_program_test_state_t;

typedef class _ebpf_map_test_state
{
  public:
    _ebpf_map_test_state(ebpf_map_type_t type)
    {
        ebpf_utf8_string_t name{(uint8_t*)"test", 4};
        ebpf_map_definition_in_memory_t definition{
            sizeof(ebpf_map_definition_in_memory_t), type, sizeof(uint32_t), sizeof(uint64_t), ebpf_get_cpu_count()};

        REQUIRE(
            ebpf_map_create(&name, &definition, reinterpret_cast<uintptr_t>(ebpf_handle_invalid), &map) ==
            EBPF_SUCCESS);

        for (uint32_t i = 0; i < ebpf_get_cpu_count(); i++) {
            uint64_t value = 0;
            ebpf_map_update_entry(map, 0, (uint8_t*)&i, 0, (uint8_t*)&value, EBPF_ANY, EBPF_MAP_FLAG_HELPER);
        }
    }
    ~_ebpf_map_test_state() { ebpf_object_release_reference((ebpf_object_t*)map); }

    void
    test_find_read(uint32_t cpu_id)
    {
        uint32_t key = cpu_id;
        volatile uint64_t* value = nullptr;

        ebpf_epoch_enter();
        ebpf_map_find_entry(map, 0, (uint8_t*)&key, 0, (uint8_t*)&value, EBPF_MAP_FLAG_HELPER);
        uint64_t local = *value;
        UNREFERENCED_PARAMETER(local);
        ebpf_epoch_exit();
    }

    void
    test_find_write(uint32_t cpu_id)
    {
        uint32_t key = cpu_id;
        uint64_t* value = nullptr;
        ebpf_epoch_enter();
        ebpf_map_find_entry(map, 0, (uint8_t*)&key, 0, (uint8_t*)&value, EBPF_MAP_FLAG_HELPER);
        (*value)++;
        ebpf_epoch_exit();
    }

    void
    test_update(uint32_t cpu_id)
    {
        uint32_t key = cpu_id;
        uint64_t value = 0;
        ebpf_epoch_enter();
        ebpf_map_update_entry(map, 0, (uint8_t*)&key, 0, (uint8_t*)&value, EBPF_ANY, EBPF_MAP_FLAG_HELPER);
        ebpf_epoch_exit();
    }

  private:
    ebpf_map_t* map;
    _test_helper_end_to_end test_helper;
} ebpf_map_test_state_t;

static ebpf_hash_table_test_state_t* _ebpf_hash_table_test_state_instance = nullptr;
static ebpf_program_test_state_t* _ebpf_program_test_state_instance = nullptr;
static ebpf_map_test_state_t* _ebpf_map_test_state_instance = nullptr;

static void
_ebpf_hash_table_test_find()
{
    _ebpf_hash_table_test_state_instance->test_find();
}

static void
_ebpf_hash_table_test_next_key()
{
    _ebpf_hash_table_test_state_instance->test_next_key();
}

static void
_ebpf_hash_table_test_replace_value(uint32_t current_cpu)
{
    _ebpf_hash_table_test_state_instance->test_replace_value(current_cpu);
}

static void
_ebpf_hash_table_test_replace_value_overlap()
{
    _ebpf_hash_table_test_state_instance->test_replace_value_overlap();
}

static void
_ebpf_program_invoke()
{
    _ebpf_program_test_state_instance->test(nullptr);
}

static void
_map_find_read_test(uint32_t cpu_id)
{
    _ebpf_map_test_state_instance->test_find_read(cpu_id);
}

static void
_map_find_write_test(uint32_t cpu_id)
{
    _ebpf_map_test_state_instance->test_find_write(cpu_id);
}

static void
_map_update_test(uint32_t cpu_id)
{
    _ebpf_map_test_state_instance->test_update(cpu_id);
}

static const char*
_ebpf_map_type_t_to_string(ebpf_map_type_t type)
{
    switch (type) {
    case BPF_MAP_TYPE_UNSPECIFIED:
        return "BPF_MAP_TYPE_UNSPECIFIED";
    case BPF_MAP_TYPE_HASH:
        return "BPF_MAP_TYPE_HASH";
    case BPF_MAP_TYPE_ARRAY:
        return "BPF_MAP_TYPE_ARRAY";
    case BPF_MAP_TYPE_PROG_ARRAY:
        return "BPF_MAP_TYPE_PROG_ARRAY";
    case BPF_MAP_TYPE_PERCPU_HASH:
        return "BPF_MAP_TYPE_PERCPU_HASH";
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        return "BPF_MAP_TYPE_PERCPU_ARRAY";
    case BPF_MAP_TYPE_HASH_OF_MAPS:
        return "BPF_MAP_TYPE_HASH_OF_MAPS";
    case BPF_MAP_TYPE_ARRAY_OF_MAPS:
        return "BPF_MAP_TYPE_ARRAY_OF_MAPS";
    default:
        return "Error";
    }
}

template <ebpf_map_type_t map_type>
void
test_bpf_map_lookup_elem_read(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    ebpf_map_test_state_t map_test_state(map_type);
    _ebpf_map_test_state_instance = &map_test_state;
    std::string name = __FUNCTION__;
    name += "<";
    name += _ebpf_map_type_t_to_string(map_type);
    name += ">";
    _performance_measure measure(name.c_str(), preemptible, _map_find_read_test, iterations);
    measure.run_test();
}

template <ebpf_map_type_t map_type>
void
test_bpf_map_lookup_elem_write(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    ebpf_map_test_state_t map_test_state(map_type);
    _ebpf_map_test_state_instance = &map_test_state;
    std::string name = __FUNCTION__;
    name += "<";
    name += _ebpf_map_type_t_to_string(map_type);
    name += ">";
    _performance_measure measure(name.c_str(), preemptible, _map_find_write_test, iterations);
    measure.run_test();
}

template <ebpf_map_type_t map_type>
void
test_bpf_map_update_elem(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    ebpf_map_test_state_t map_test_state(map_type);
    _ebpf_map_test_state_instance = &map_test_state;
    std::string name = __FUNCTION__;
    name += "<";
    name += _ebpf_map_type_t_to_string(map_type);
    name += ">";
    _performance_measure measure(name.c_str(), preemptible, _map_update_test, iterations);
    measure.run_test();
}

void
test_bpf_get_prandom_u32(bool preemptible)
{
    REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    _performance_measure measure(__FUNCTION__, preemptible, _perf_bpf_get_prandom_u32, iterations);
    measure.run_test();
    ebpf_core_terminate();
}

void
test_bpf_ktime_get_boot_ns(bool preemptible)
{
    REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    _performance_measure measure(__FUNCTION__, preemptible, _perf_bpf_ktime_get_boot_ns, iterations);
    measure.run_test();
    ebpf_core_terminate();
}

void
test_bpf_get_smp_processor_id(bool preemptible)
{
    REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    _performance_measure measure(__FUNCTION__, preemptible, _perf_bpf_get_smp_processor_id, iterations);
    measure.run_test();
    ebpf_core_terminate();
}

extern bool _ebpf_platform_is_preemptible;

void
test_epoch_enter_exit(bool preemptible)
{
    REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT * 10;
    _performance_measure measure(__FUNCTION__, preemptible, _perf_epoch_enter_exit, iterations);
    measure.run_test();
    ebpf_core_terminate();
}

void
test_epoch_enter_exit_alloc_free(bool preemptible)
{
    REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT * 10;
    _performance_measure measure(__FUNCTION__, preemptible, _perf_epoch_enter_alloc_free_exit, iterations);
    measure.run_test();
    ebpf_core_terminate();
}

void
test_ebpf_hash_table_find(bool preemptible)
{
    _ebpf_hash_table_test_state instance;
    _ebpf_hash_table_test_state_instance = &instance;
    _performance_measure measure(__FUNCTION__, preemptible, _ebpf_hash_table_test_find);
    measure.run_test(instance.multiplier());
}

void
test_ebpf_hash_table_next_key(bool preemptible)
{
    _ebpf_hash_table_test_state instance;
    _ebpf_hash_table_test_state_instance = &instance;
    _performance_measure measure(__FUNCTION__, preemptible, _ebpf_hash_table_test_next_key);
    measure.run_test(instance.multiplier());
}

void
test_ebpf_hash_table_update(bool preemptible)
{
    _ebpf_hash_table_test_state instance;
    _ebpf_hash_table_test_state_instance = &instance;
    _performance_measure measure(
        __FUNCTION__, preemptible, _ebpf_hash_table_test_replace_value, PERFORMANCE_MEASURE_ITERATION_COUNT / 10);
    measure.run_test(instance.multiplier());
}

void
test_ebpf_hash_table_update_overlapping(bool preemptible)
{
    _ebpf_hash_table_test_state instance;
    _ebpf_hash_table_test_state_instance = &instance;
    _performance_measure measure(
        __FUNCTION__,
        preemptible,
        _ebpf_hash_table_test_replace_value_overlap,
        PERFORMANCE_MEASURE_ITERATION_COUNT / 10);
    measure.run_test(instance.multiplier());
}

void
test_program_invoke_jit(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT * 10;
    std::vector<ebpf_instruction_t> byte_code = {{EBPF_OP_MOV_IMM, 0, 0, 0, 42}, {EBPF_OP_EXIT}};
    _ebpf_program_test_state program_state(byte_code);
    _ebpf_program_test_state_instance = &program_state;
    program_state.prepare_jit_program();

    _performance_measure measure(__FUNCTION__, preemptible, _ebpf_program_invoke, iterations);
    measure.run_test();
}

void
test_program_invoke_interpret(bool preemptible)
{

    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT * 10;
    std::vector<ebpf_instruction_t> byte_code = {{EBPF_OP_MOV_IMM, 0, 0, 0, 42}, {EBPF_OP_EXIT}};
    _ebpf_program_test_state program_state(byte_code);
    _ebpf_program_test_state_instance = &program_state;
    program_state.prepare_interpret_program();

    _performance_measure measure(__FUNCTION__, preemptible, _ebpf_program_invoke, iterations);
    measure.run_test();
}

PERF_TEST(test_epoch_enter_exit);
PERF_TEST(test_epoch_enter_exit_alloc_free);
PERF_TEST(test_ebpf_hash_table_find);
PERF_TEST(test_ebpf_hash_table_next_key);
PERF_TEST(test_ebpf_hash_table_update);
PERF_TEST(test_ebpf_hash_table_update_overlapping);
PERF_TEST(test_program_invoke_jit);
PERF_TEST(test_program_invoke_interpret);

PERF_TEST(test_bpf_get_prandom_u32);
PERF_TEST(test_bpf_ktime_get_boot_ns);
PERF_TEST(test_bpf_get_smp_processor_id);

PERF_TEST(test_bpf_map_lookup_elem_read<BPF_MAP_TYPE_HASH>);
PERF_TEST(test_bpf_map_lookup_elem_read<BPF_MAP_TYPE_ARRAY>);
PERF_TEST(test_bpf_map_lookup_elem_read<BPF_MAP_TYPE_PERCPU_HASH>);
PERF_TEST(test_bpf_map_lookup_elem_read<BPF_MAP_TYPE_PERCPU_ARRAY>);

PERF_TEST(test_bpf_map_lookup_elem_write<BPF_MAP_TYPE_HASH>);
PERF_TEST(test_bpf_map_lookup_elem_write<BPF_MAP_TYPE_ARRAY>);
PERF_TEST(test_bpf_map_lookup_elem_write<BPF_MAP_TYPE_PERCPU_HASH>);
PERF_TEST(test_bpf_map_lookup_elem_write<BPF_MAP_TYPE_PERCPU_ARRAY>);

PERF_TEST(test_bpf_map_update_elem<BPF_MAP_TYPE_HASH>);
PERF_TEST(test_bpf_map_update_elem<BPF_MAP_TYPE_ARRAY>);
PERF_TEST(test_bpf_map_update_elem<BPF_MAP_TYPE_PERCPU_HASH>);
PERF_TEST(test_bpf_map_update_elem<BPF_MAP_TYPE_PERCPU_ARRAY>);