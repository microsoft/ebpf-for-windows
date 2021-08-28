// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "performance_measure.h"

#include "catch_wrapper.hpp"
#include "ebpf.h"
#include "ebpf_epoch.h"
#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "helpers.h"
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
_perf_epoch_enter_exit_alloc_free()
{
    ebpf_epoch_enter();
    void* p = ebpf_epoch_allocate(10);
    ebpf_epoch_free(p);
    memset(p, 0xAA, 10);
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
                    nullptr,
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
    test_replace_value()
    {
        uint64_t value = 12345678;
        uint32_t start = cpu_count * 4;
        uint32_t end = (cpu_count + 1) * 4;
        // Update non-conflicting keys
        for (uint32_t i = 0; i < cpu_count; i++) {
            for (uint32_t index = start; index < end; index++) {
                ebpf_epoch_enter();
                ebpf_hash_table_update(
                    table,
                    reinterpret_cast<uint8_t*>(&keys[index]),
                    reinterpret_cast<uint8_t*>(&value),
                    nullptr,
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
                nullptr,
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
    setup_jit_program()
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
    setup_interpret_program()
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

static ebpf_hash_table_test_state_t* _ebpf_hash_table_test_state_instance = nullptr;
static ebpf_program_test_state_t* _ebpf_program_test_state_instance = nullptr;

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
_ebpf_hash_table_test_replace_value()
{
    _ebpf_hash_table_test_state_instance->test_replace_value();
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
    _performance_measure measure(__FUNCTION__, preemptible, _perf_epoch_enter_exit_alloc_free, iterations);
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
    program_state.setup_jit_program();

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
    program_state.setup_interpret_program();

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
