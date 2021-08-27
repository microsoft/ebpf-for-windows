// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "performance_measure.h"

static void
_perf_epoch_enter_exit()
{
    ebpf_epoch_enter();
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
        ebpf_epoch_enter();
        keys.resize(static_cast<size_t>(ebpf_get_cpu_count()) * 4ull);
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
        uint32_t start = ebpf_get_current_cpu() * 4;
        uint32_t end = (ebpf_get_current_cpu() + 1) * 4;
        // Update non-conflicting keys
        for (uint32_t i = 0; i < ebpf_get_current_cpu(); i++) {
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

    size_t
    multiplier()
    {
        return keys.size();
    }

    ~_ebpf_hash_table_test_state() { ebpf_hash_table_destroy(table); }

  private:
    ebpf_hash_table_t* table;
    std::vector<uint32_t> keys;

} ebpf_hash_table_test_state_t;

static ebpf_hash_table_test_state_t* _ebpf_hash_table_test_state_instance = nullptr;

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

TEST_CASE("epoch_enter_exit", "[performance]")
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    iterations *= ebpf_get_cpu_count();
    iterations *= 4;
    _performance_measure measure(_perf_epoch_enter_exit, iterations);
    auto average_duration = measure.run_test();

    printf("perf_epoch_enter_exit:%.0fns\n", average_duration);
}

TEST_CASE("ebpf_hash_table_find", "[performance]")
{
    _ebpf_hash_table_test_state instance;
    _ebpf_hash_table_test_state_instance = &instance;
    _performance_measure measure(_ebpf_hash_table_test_find);
    auto average_duration = measure.run_test() / instance.multiplier();

    printf("perf_ebpf_hash_table_find:%.0fns\n", average_duration);
}

TEST_CASE("ebpf_hash_table_next_key", "[performance]")
{
    _ebpf_hash_table_test_state instance;
    _ebpf_hash_table_test_state_instance = &instance;
    _performance_measure measure(_ebpf_hash_table_test_next_key);
    auto average_duration = measure.run_test() / instance.multiplier();

    printf("perf_ebpf_hash_table_next_key:%.0fns\n", average_duration);
}

TEST_CASE("ebpf_hash_table_update", "[performance]")
{
    _ebpf_hash_table_test_state instance;
    _ebpf_hash_table_test_state_instance = &instance;
    _performance_measure measure(_ebpf_hash_table_test_replace_value, PERFORMANCE_MEASURE_ITERATION_COUNT / 10);
    auto average_duration = measure.run_test() / instance.multiplier();

    printf("perf_ebpf_hash_table_update:%.0fns\n", average_duration);
}
