// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define TEST_AREA "ExecutionContext"

#include "performance.h"

extern "C"
{
#include "ubpf.h"
}

#include <numeric>
#include <optional>

typedef class _ebpf_program_test_state
{
  public:
    _ebpf_program_test_state(std::vector<ebpf_instruction_t> byte_code)
        : byte_code(byte_code), program_info_provider(nullptr)
    {
        ebpf_program_parameters_t parameters = {EBPF_PROGRAM_TYPE_XDP};
        REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);

        // Create the program info provider.  We can only do this after calling
        // ebpf_core_initiate() since that initializes the interface GUID.
        program_info_provider = new _program_info_provider(EBPF_PROGRAM_TYPE_XDP);

        REQUIRE(ebpf_program_create(&program) == EBPF_SUCCESS);

        REQUIRE(ebpf_program_initialize(program, &parameters) == EBPF_SUCCESS);
    }
    ~_ebpf_program_test_state()
    {
        ebpf_object_release_reference(reinterpret_cast<ebpf_core_object_t*>(program));
        delete program_info_provider;
        ebpf_core_terminate();
    }

    void
    prepare_jit_program()
    {
        ubpf_vm* vm = ubpf_create();
        REQUIRE(vm != nullptr);

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
            ebpf_program_load_code(program, EBPF_CODE_JIT, nullptr, machine_code.data(), machine_code.size()) ==
            EBPF_SUCCESS);
    }

    void
    prepare_interpret_program()
    {
        REQUIRE(
            ebpf_program_load_code(
                program,
                EBPF_CODE_EBPF,
                nullptr,
                reinterpret_cast<uint8_t*>(byte_code.data()),
                byte_code.size() * sizeof(ebpf_instruction_t)) == EBPF_SUCCESS);
    }

    void
    test(void* context)
    {
        uint32_t result;
        ebpf_execution_context_state_t state = {0};
        ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
        ebpf_get_execution_context_state(&state);
        ebpf_program_invoke(program, context, &result, &state);
        ebpf_epoch_exit(epoch_state);
    }

  private:
    ebpf_program_t* program;
    std::vector<ebpf_instruction_t> byte_code;
    _program_info_provider* program_info_provider;
} ebpf_program_test_state_t;

typedef class _ebpf_map_test_state
{
  public:
    _ebpf_map_test_state(ebpf_map_type_t type, std::optional<uint32_t> map_size = {})
    {
        ebpf_utf8_string_t name{(uint8_t*)"test", 4};
        REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
        ebpf_map_definition_in_memory_t definition{
            type, sizeof(uint32_t), sizeof(uint64_t), map_size.has_value() ? map_size.value() : ebpf_get_cpu_count()};

        REQUIRE(ebpf_map_create(&name, &definition, ebpf_handle_invalid, &map) == EBPF_SUCCESS);

        for (uint32_t i = 0; i < definition.max_entries; i++) {
            uint64_t value = 0;
            (void)ebpf_map_update_entry(map, 0, (uint8_t*)&i, 0, (uint8_t*)&value, EBPF_ANY, EBPF_MAP_FLAG_HELPER);
        }
        // Make the active key range 10% of the map size.
        lru_key_range = definition.max_entries / 10;
        // Start at the end of the key range so that we start evicting keys.
        lru_key_base = definition.max_entries;
    }
    ~_ebpf_map_test_state()
    {
        ebpf_object_release_reference((ebpf_core_object_t*)map);
        ebpf_core_terminate();
    }

    void
    test_find_read(uint32_t cpu_id)
    {
        uint32_t key = cpu_id;
        volatile uint64_t* value = nullptr;

        ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
        (void)ebpf_map_find_entry(map, 0, (uint8_t*)&key, 0, (uint8_t*)&value, EBPF_MAP_FLAG_HELPER);
        uint64_t local = *value;
        UNREFERENCED_PARAMETER(local);
        ebpf_epoch_exit(epoch_state);
    }

    void
    test_find_write(uint32_t cpu_id)
    {
        uint32_t key = cpu_id;
        uint64_t* value = nullptr;
        ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
        (void)ebpf_map_find_entry(map, 0, (uint8_t*)&key, 0, (uint8_t*)&value, EBPF_MAP_FLAG_HELPER);
        (*value)++;
        ebpf_epoch_exit(epoch_state);
    }

    void
    test_update(uint32_t cpu_id)
    {
        uint32_t key = cpu_id;
        uint64_t value = 0;
        ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
        (void)ebpf_map_update_entry(map, 0, (uint8_t*)&key, 0, (uint8_t*)&value, EBPF_ANY, EBPF_MAP_FLAG_HELPER);
        ebpf_epoch_exit(epoch_state);
    }

    void
    test_update_lru()
    {
        uint32_t key = ebpf_random_uint32();
        uint64_t value = 0;
        ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
        (void)ebpf_map_update_entry(map, 0, (uint8_t*)&key, 0, (uint8_t*)&value, EBPF_ANY, EBPF_MAP_FLAG_HELPER);
        ebpf_epoch_exit(epoch_state);
    }

    void
    test_rolling_update_lru(uint32_t cpu_id)
    {
        uint64_t value = 0;
        static uint64_t iteration = 0;
        // Rotate key every 10 lookups.
        if (cpu_id == 0) {
            iteration++;
            if (iteration % 10 == 0) {
                lru_key_base++;
            }
        }
        uint32_t key = lru_key_base + (ebpf_random_uint32() % lru_key_range);
        ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
        // Check if the current key is present.
        if (ebpf_map_find_entry(map, 0, (uint8_t*)&key, 0, (uint8_t*)&value, EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS) {
            // Cache hit.
        } else {
            // Cache miss. Add it to the LRU map.
            (void)ebpf_map_update_entry(map, 0, (uint8_t*)&key, 0, (uint8_t*)&value, EBPF_ANY, EBPF_MAP_FLAG_HELPER);
        }
        ebpf_epoch_exit(epoch_state);
    }

  private:
    // Searches are performed in the LRU map using keys in the range [lru_key_base, lru_key_base + lru_key_range).
    uint32_t lru_key_base;
    uint32_t lru_key_range;
    ebpf_map_t* map;
} ebpf_map_test_state_t;

typedef class _ebpf_map_lpm_trie_test_state
{
  public:
    _ebpf_map_lpm_trie_test_state() : map(nullptr) { REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS); }

    void
    populate_ipv4_routes(size_t route_count)
    {
        ebpf_utf8_string_t name{(uint8_t*)"ipv4_route_table", 11};
        ebpf_map_definition_in_memory_t definition{
            BPF_MAP_TYPE_LPM_TRIE, sizeof(uint32_t) * 2, sizeof(uint64_t), static_cast<uint32_t>(route_count)};

        REQUIRE(ebpf_map_create(&name, &definition, ebpf_handle_invalid, &map) == EBPF_SUCCESS);

        // Prefix Length Distributions from https://bgp.potaroo.net/as2.0/bgp-active.html
        std::vector<size_t> ipv4_prefix_length_distribution{
            0,    0,     0,     0,     0,     0,      0,     16,     13,   41, 102, 306, 596, 1215, 2090, 13647,
            8391, 14216, 25741, 43665, 53098, 109281, 97781, 523876, 1459, 0,  0,   1,   0,   1,    0,    1,
        };

        size_t total = 0;
        total = std::accumulate(ipv4_prefix_length_distribution.begin(), ipv4_prefix_length_distribution.end(), total);
        for (size_t prefix_length = 0; prefix_length < ipv4_prefix_length_distribution.size(); prefix_length++) {
            size_t scaled_size = ipv4_prefix_length_distribution[prefix_length] * route_count / total;
            for (size_t count = 0; count < scaled_size; count++) {
                ipv4_routes.push_back({static_cast<uint32_t>(prefix_length + 1), ebpf_random_uint32()});
            }
        }
        for (auto& [prefix_length, prefix] : ipv4_routes) {
            std::vector<uint8_t> prefix_bytes(sizeof(uint32_t));
            *reinterpret_cast<uint32_t*>(prefix_bytes.data()) = prefix;
            populate_route(prefix_bytes, prefix_length);
        }
    }

    void
    populate_route(const std::vector<uint8_t>& prefix, uint32_t length)
    {
        std::vector<uint8_t> value(sizeof(uint64_t));
        std::vector<uint8_t> key(prefix.size() + sizeof(length));
        memcpy(key.data(), &length, sizeof(length));
        std::copy(prefix.begin(), prefix.end(), key.begin() + sizeof(length));
        ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
        REQUIRE(
            ebpf_map_update_entry(map, key.size(), key.data(), value.size(), value.data(), EBPF_ANY, 0) ==
            EBPF_SUCCESS);
        ebpf_epoch_exit(epoch_state);
    }

    void
    test_find_ipv4_route()
    {
        struct _key
        {
            uint32_t prefix_length;
            uint32_t prefix;
        } ipv4_key = {32, ipv4_routes[ebpf_random_uint32() % ipv4_routes.size()].second};
        volatile uint64_t* value = nullptr;

        ebpf_epoch_state_t* epoch_state = ebpf_epoch_enter();
        (void)ebpf_map_find_entry(map, sizeof(ipv4_key), (uint8_t*)&ipv4_key, sizeof(value), (uint8_t*)&value, 0);
        UNREFERENCED_PARAMETER(value);
        ebpf_epoch_exit(epoch_state);
    }

    ~_ebpf_map_lpm_trie_test_state()
    {
        ebpf_object_release_reference((ebpf_core_object_t*)map);
        ebpf_core_terminate();
    }

  private:
    ebpf_map_t* map;
    std::vector<std::pair<uint32_t, uint32_t>> ipv4_routes;
} ebpf_map_lpm_trie_test_state_t;

static ebpf_program_test_state_t* _ebpf_program_test_state_instance = nullptr;
static ebpf_map_test_state_t* _ebpf_map_test_state_instance = nullptr;
static ebpf_map_lpm_trie_test_state_t* _ebpf_map_lpm_trie_test_state_instance = nullptr;

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

static void
_map_update_lru_test()
{
    _ebpf_map_test_state_instance->test_update_lru();
}

static void
_map_lookup_lru_test(uint32_t cpu_id)
{
    _ebpf_map_test_state_instance->test_rolling_update_lru(cpu_id);
}

static void
_lpm_trie_ipv4_find()
{
    _ebpf_map_lpm_trie_test_state_instance->test_find_ipv4_route();
}

static const char*
_ebpf_map_type_t_to_string(ebpf_map_type_t type)
{
    switch (type) {
    case BPF_MAP_TYPE_UNSPEC:
        return "BPF_MAP_TYPE_UNSPEC";
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
    case BPF_MAP_TYPE_LRU_HASH:
        return "BPF_MAP_TYPE_LRU_HASH";
    case BPF_MAP_TYPE_RINGBUF:
        return "BPF_MAP_TYPE_RINGBUF";
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

#define LRU_MAP_SIZE 8192

template <ebpf_map_type_t map_type>
void
test_bpf_map_update_lru_elem(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT / 10;
    ebpf_map_test_state_t map_test_state(map_type, {LRU_MAP_SIZE});
    _ebpf_map_test_state_instance = &map_test_state;
    std::string name = __FUNCTION__;
    name += "<";
    name += _ebpf_map_type_t_to_string(map_type);
    name += ">";
    _performance_measure measure(name.c_str(), preemptible, _map_update_lru_test, iterations);
    measure.run_test();
}

template <ebpf_map_type_t map_type>
void
test_bpf_map_lookup_lru_elem(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT / 10;
    ebpf_map_test_state_t map_test_state(map_type, {LRU_MAP_SIZE});
    _ebpf_map_test_state_instance = &map_test_state;
    std::string name = __FUNCTION__;
    name += "<";
    name += _ebpf_map_type_t_to_string(map_type);
    name += ">";
    _performance_measure measure(name.c_str(), preemptible, _map_lookup_lru_test, iterations);
    measure.run_test();
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

template <size_t route_count>
void
test_lpm_trie_ipv4(bool preemptible)
{
    size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT;
    _ebpf_map_lpm_trie_test_state lpm_trie_state;
    lpm_trie_state.populate_ipv4_routes(route_count);
    _ebpf_map_lpm_trie_test_state_instance = &lpm_trie_state;
    std::string name = __FUNCTION__;
    name += "<";
    name += std::to_string(route_count);
    name += ">";

    _performance_measure measure(name.c_str(), preemptible, _lpm_trie_ipv4_find, iterations);
    measure.run_test();
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
PERF_TEST(test_program_invoke_jit);
#endif
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
PERF_TEST(test_program_invoke_interpret);
#endif
PERF_TEST(test_bpf_map_lookup_elem_read<BPF_MAP_TYPE_HASH>);
PERF_TEST(test_bpf_map_lookup_elem_read<BPF_MAP_TYPE_ARRAY>);
PERF_TEST(test_bpf_map_lookup_elem_read<BPF_MAP_TYPE_PERCPU_HASH>);
PERF_TEST(test_bpf_map_lookup_elem_read<BPF_MAP_TYPE_PERCPU_ARRAY>);
PERF_TEST(test_bpf_map_lookup_elem_read<BPF_MAP_TYPE_LRU_HASH>);

PERF_TEST(test_bpf_map_lookup_elem_write<BPF_MAP_TYPE_HASH>);
PERF_TEST(test_bpf_map_lookup_elem_write<BPF_MAP_TYPE_ARRAY>);
PERF_TEST(test_bpf_map_lookup_elem_write<BPF_MAP_TYPE_PERCPU_HASH>);
PERF_TEST(test_bpf_map_lookup_elem_write<BPF_MAP_TYPE_PERCPU_ARRAY>);
PERF_TEST(test_bpf_map_lookup_elem_write<BPF_MAP_TYPE_LRU_HASH>);

PERF_TEST(test_bpf_map_update_elem<BPF_MAP_TYPE_HASH>);
PERF_TEST(test_bpf_map_update_elem<BPF_MAP_TYPE_ARRAY>);
PERF_TEST(test_bpf_map_update_elem<BPF_MAP_TYPE_PERCPU_HASH>);
PERF_TEST(test_bpf_map_update_elem<BPF_MAP_TYPE_PERCPU_ARRAY>);
PERF_TEST(test_bpf_map_update_elem<BPF_MAP_TYPE_LRU_HASH>);

PERF_TEST(test_bpf_map_update_lru_elem<BPF_MAP_TYPE_LRU_HASH>);
PERF_TEST(test_bpf_map_lookup_lru_elem<BPF_MAP_TYPE_LRU_HASH>);

PERF_TEST(test_lpm_trie_ipv4<1024>);
PERF_TEST(test_lpm_trie_ipv4<1024 * 16>);
PERF_TEST(test_lpm_trie_ipv4<1024 * 256>);
PERF_TEST(test_lpm_trie_ipv4<1024 * 1024>);
