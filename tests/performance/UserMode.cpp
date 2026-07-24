// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_PERFORMANCE_TESTS

#define TEST_AREA "UserMode"

#include "performance.h"
#include "mock.h"
#include "test_helper.hpp"

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include <optional>

typedef class _ebpf_user_mode_map_test_state
{
  public:
    _ebpf_user_mode_map_test_state(ebpf_map_type_t type, std::optional<uint32_t> map_size = {})
    {
        // Initialize the test helper (sets up the user-mode mock API stack).
        test_helper.initialize();

        cpu_count = ebpf_get_cpu_count();

        bool is_percpu = (type == BPF_MAP_TYPE_PERCPU_HASH || type == BPF_MAP_TYPE_PERCPU_ARRAY);
        // For percpu maps, the user-mode API requires a value buffer of value_size * cpu_count bytes.
        value_buf_size = is_percpu ? sizeof(uint64_t) * cpu_count : sizeof(uint64_t);

        uint32_t size = map_size.has_value() ? map_size.value() : cpu_count;

        // Create the map using the user-mode API.
        map_fd = bpf_map_create(type, "perf_test_map", sizeof(uint32_t), sizeof(uint64_t), size, nullptr);
        REQUIRE(map_fd > 0);

        // Pre-populate the map.
        std::vector<uint8_t> value(value_buf_size, 0);
        for (uint32_t i = 0; i < size; i++) {
            REQUIRE(bpf_map_update_elem(map_fd, &i, value.data(), BPF_ANY) == 0);
        }

        // Pre-allocate per-CPU value buffers to avoid allocations in the hot path.
        per_cpu_bufs.resize(cpu_count, std::vector<uint8_t>(value_buf_size, 0));

        // Make the active key range 10% of the map size.
        lru_key_range = (size / 10 > 0) ? size / 10 : 1;
        // Start at the end of the key range so that we start evicting keys.
        lru_key_base = size;
    }

    ~_ebpf_user_mode_map_test_state()
    {
        if (map_fd > 0) {
            Platform::_close(map_fd);
        }
    }

    void
    test_lookup(uint32_t cpu_id)
    {
        uint32_t key = cpu_id;
        // Since this is a perf test, not checking the result.
        (void)bpf_map_lookup_elem(map_fd, &key, per_cpu_bufs[cpu_id].data());
    }

    void
    test_update(uint32_t cpu_id)
    {
        uint32_t key = cpu_id;
        // Since this is a perf test, not checking the result.
        (void)bpf_map_update_elem(map_fd, &key, per_cpu_bufs[cpu_id].data(), BPF_ANY);
    }

    void
    test_update_lru()
    {
        uint32_t key = ebpf_random_uint32();
        uint64_t value = 0;
        // Since this is a perf test, not checking the result.
        (void)bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    }

    void
    test_rolling_update_lru(uint32_t cpu_id)
    {
        static uint64_t iteration = 0;
        // Rotate key every 10 lookups.
        if (cpu_id == 0) {
            iteration++;
            if (iteration % 10 == 0) {
                lru_key_base++;
            }
        }
        uint32_t key = lru_key_base + (ebpf_random_uint32() % lru_key_range);
        // Check if the current key is present.
        if (bpf_map_lookup_elem(map_fd, &key, per_cpu_bufs[cpu_id].data()) != 0) {
            // Cache miss. Add it to the LRU map.
            (void)bpf_map_update_elem(map_fd, &key, per_cpu_bufs[cpu_id].data(), BPF_ANY);
        }
    }

  private:
    _test_helper_end_to_end test_helper;
    int map_fd = -1;
    uint32_t cpu_count;
    uint32_t value_buf_size;
    uint32_t lru_key_range;
    uint32_t lru_key_base;
    std::vector<std::vector<uint8_t>> per_cpu_bufs;
} ebpf_user_mode_map_test_state_t;

static ebpf_user_mode_map_test_state_t* _ebpf_user_mode_map_test_state_instance = nullptr;

static void
_user_mode_map_lookup_test(uint32_t cpu_id)
{
    _ebpf_user_mode_map_test_state_instance->test_lookup(cpu_id);
}

static void
_user_mode_map_update_test(uint32_t cpu_id)
{
    _ebpf_user_mode_map_test_state_instance->test_update(cpu_id);
}

static void
_user_mode_map_update_lru_test()
{
    _ebpf_user_mode_map_test_state_instance->test_update_lru();
}

static void
_user_mode_map_lookup_lru_test(uint32_t cpu_id)
{
    _ebpf_user_mode_map_test_state_instance->test_rolling_update_lru(cpu_id);
}

static const char*
_ebpf_map_type_to_string(ebpf_map_type_t type)
{
    switch (type) {
    case BPF_MAP_TYPE_HASH:
        return "BPF_MAP_TYPE_HASH";
    case BPF_MAP_TYPE_ARRAY:
        return "BPF_MAP_TYPE_ARRAY";
    case BPF_MAP_TYPE_PERCPU_HASH:
        return "BPF_MAP_TYPE_PERCPU_HASH";
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        return "BPF_MAP_TYPE_PERCPU_ARRAY";
    case BPF_MAP_TYPE_LRU_HASH:
        return "BPF_MAP_TYPE_LRU_HASH";
    default:
        return "Error";
    }
}

#define USER_MODE_LRU_MAP_SIZE 8192

template <ebpf_map_type_t map_type>
void
test_user_mode_bpf_map_lookup_elem(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    ebpf_user_mode_map_test_state_t map_test_state(map_type);
    _ebpf_user_mode_map_test_state_instance = &map_test_state;
    std::string name = __FUNCTION__;
    name += "<";
    name += _ebpf_map_type_to_string(map_type);
    name += ">";
    _performance_measure measure(name.c_str(), preemptible, _user_mode_map_lookup_test, iterations);
    measure.run_test();
}

template <ebpf_map_type_t map_type>
void
test_user_mode_bpf_map_update_elem(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    ebpf_user_mode_map_test_state_t map_test_state(map_type);
    _ebpf_user_mode_map_test_state_instance = &map_test_state;
    std::string name = __FUNCTION__;
    name += "<";
    name += _ebpf_map_type_to_string(map_type);
    name += ">";
    _performance_measure measure(name.c_str(), preemptible, _user_mode_map_update_test, iterations);
    measure.run_test();
}

template <ebpf_map_type_t map_type>
void
test_user_mode_bpf_map_update_lru_elem(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT / 10;
    ebpf_user_mode_map_test_state_t map_test_state(map_type, {USER_MODE_LRU_MAP_SIZE});
    _ebpf_user_mode_map_test_state_instance = &map_test_state;
    std::string name = __FUNCTION__;
    name += "<";
    name += _ebpf_map_type_to_string(map_type);
    name += ">";
    _performance_measure measure(name.c_str(), preemptible, _user_mode_map_update_lru_test, iterations);
    measure.run_test();
}

template <ebpf_map_type_t map_type>
void
test_user_mode_bpf_map_lookup_lru_elem(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT / 10;
    ebpf_user_mode_map_test_state_t map_test_state(map_type, {USER_MODE_LRU_MAP_SIZE});
    _ebpf_user_mode_map_test_state_instance = &map_test_state;
    std::string name = __FUNCTION__;
    name += "<";
    name += _ebpf_map_type_to_string(map_type);
    name += ">";
    _performance_measure measure(name.c_str(), preemptible, _user_mode_map_lookup_lru_test, iterations);
    measure.run_test();
}

PERF_TEST(test_user_mode_bpf_map_lookup_elem<BPF_MAP_TYPE_HASH>);
PERF_TEST(test_user_mode_bpf_map_lookup_elem<BPF_MAP_TYPE_ARRAY>);
PERF_TEST(test_user_mode_bpf_map_lookup_elem<BPF_MAP_TYPE_PERCPU_HASH>);
PERF_TEST(test_user_mode_bpf_map_lookup_elem<BPF_MAP_TYPE_PERCPU_ARRAY>);
PERF_TEST(test_user_mode_bpf_map_lookup_elem<BPF_MAP_TYPE_LRU_HASH>);

PERF_TEST(test_user_mode_bpf_map_update_elem<BPF_MAP_TYPE_HASH>);
PERF_TEST(test_user_mode_bpf_map_update_elem<BPF_MAP_TYPE_ARRAY>);
PERF_TEST(test_user_mode_bpf_map_update_elem<BPF_MAP_TYPE_PERCPU_HASH>);
PERF_TEST(test_user_mode_bpf_map_update_elem<BPF_MAP_TYPE_PERCPU_ARRAY>);
PERF_TEST(test_user_mode_bpf_map_update_elem<BPF_MAP_TYPE_LRU_HASH>);

PERF_TEST(test_user_mode_bpf_map_update_lru_elem<BPF_MAP_TYPE_LRU_HASH>);
PERF_TEST(test_user_mode_bpf_map_lookup_lru_elem<BPF_MAP_TYPE_LRU_HASH>);
