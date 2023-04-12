// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define TEST_AREA "platform"
#include "performance.h"

static void
_perf_epoch_enter_exit()
{
    ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
    ebpf_epoch_exit(epoch_state);
}

static void
_perf_epoch_enter_alloc_free_exit()
{
    ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
    void* p = ebpf_epoch_allocate(10);
    if (p != NULL) {
        ebpf_epoch_free(p);
        // Disable C6001
        // We are intentionally modifying memory after free, but relying on epoch protection.
#pragma warning(push)
#pragma warning(disable : 6001)
        memset(p, 0xAA, 10);
#pragma warning(pop)
    }
    ebpf_epoch_exit(epoch_state);
}

static void
_perf_bpf_get_prandom_u32()
{
    ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
    ebpf_random_uint32();
    ebpf_epoch_exit(epoch_state);
}

static void
_perf_bpf_ktime_get_boot_ns()
{
    uint64_t time;
    ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
    time = ebpf_query_time_since_boot(true) * EBPF_NS_PER_FILETIME;
    ebpf_epoch_exit(epoch_state);
}

static void
_perf_bpf_ktime_get_ns()
{
    uint64_t time;
    ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
    time = ebpf_query_time_since_boot(false) * EBPF_NS_PER_FILETIME;
    ebpf_epoch_exit(epoch_state);
}

static void
_perf_bpf_get_smp_processor_id()
{
    ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
    ebpf_get_current_cpu();
    ebpf_epoch_exit(epoch_state);
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
        epoch_initiated = true;

        ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
        keys.resize(static_cast<size_t>(cpu_count) * 4ull);
        const ebpf_hash_table_creation_options_t options = {
            .key_size = sizeof(uint32_t),
            .value_size = sizeof(uint64_t),
            .bucket_count = keys.size(),
        };
        REQUIRE(ebpf_hash_table_create(&table, &options) == EBPF_SUCCESS);
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
        ebpf_epoch_exit(epoch_state);
    }
    ~_ebpf_hash_table_test_state()
    {
        ebpf_hash_table_destroy(table);

        if (epoch_initiated) {
            ebpf_epoch_terminate();
        }
        if (platform_initiated) {
            ebpf_platform_terminate();
        }
    }

    void
    test_find()
    {
        uint8_t* value;
        for (auto& key : keys) {
            ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
            // Expected to fail.
            (void)ebpf_hash_table_find(table, reinterpret_cast<uint8_t*>(&key), &value);
            ebpf_epoch_exit(epoch_state);
        }
    }

    void
    test_next_key()
    {
        uint32_t next_key;
        for (auto& key : keys) {
            ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
            // Expected to fail.
            (void)ebpf_hash_table_next_key(
                table, reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&next_key));
            ebpf_epoch_exit(epoch_state);
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
                ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
                // Expected to fail.
                (void)ebpf_hash_table_update(
                    table,
                    reinterpret_cast<uint8_t*>(&keys[index]),
                    reinterpret_cast<uint8_t*>(&value),
                    EBPF_HASH_TABLE_OPERATION_REPLACE);
                ebpf_epoch_exit(epoch_state);
            }
        }
    }

    void
    test_replace_value_overlap()
    {
        uint64_t value = 12345678;
        // Update conflicting keys
        for (auto& key : keys) {
            ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
            // Expected to fail.
            (void)ebpf_hash_table_update(
                table,
                reinterpret_cast<uint8_t*>(&key),
                reinterpret_cast<uint8_t*>(&value),
                EBPF_HASH_TABLE_OPERATION_REPLACE);
            ebpf_epoch_exit(epoch_state);
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
    bool epoch_initiated = false;
    uint32_t cpu_count;

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
_ebpf_hash_table_test_replace_value(uint32_t current_cpu)
{
    _ebpf_hash_table_test_state_instance->test_replace_value(current_cpu);
}

static void
_ebpf_hash_table_test_replace_value_overlap()
{
    _ebpf_hash_table_test_state_instance->test_replace_value_overlap();
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
test_bpf_ktime_get_ns(bool preemptible)
{
    REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    _performance_measure measure(__FUNCTION__, preemptible, _perf_bpf_ktime_get_ns, iterations);
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

PERF_TEST(test_epoch_enter_exit);
PERF_TEST(test_epoch_enter_exit_alloc_free);
PERF_TEST(test_ebpf_hash_table_find);
PERF_TEST(test_ebpf_hash_table_next_key);
PERF_TEST(test_ebpf_hash_table_update);
PERF_TEST(test_ebpf_hash_table_update_overlapping);

PERF_TEST(test_bpf_get_prandom_u32);
PERF_TEST(test_bpf_ktime_get_boot_ns);
PERF_TEST(test_bpf_ktime_get_ns);
PERF_TEST(test_bpf_get_smp_processor_id);
