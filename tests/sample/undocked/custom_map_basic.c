// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c custom_map_basic.c -o custom_map_basic_jit.o
//
// For bpf code: clang -target bpf -O2 -Werror -c custom_map_basic.c -o custom_map_basic.o
// this passes the checker

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

#define CONFIG_USE_ARRAY_MAP 1
#define CONFIG_USE_HASH_MAP 2

#define OPERATION_SUCCESS 1
#define OPERATION_FAILURE 0

struct
{
    __uint(type, BPF_MAP_TYPE_SAMPLE_HASH_MAP);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} sample_hash_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} config_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} result_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} result_value_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} array_map SEC(".maps");

static inline void
set_result(uint32_t result)
{
    uint32_t key = 0;
    bpf_map_update_elem(&result_map, &key, &result, 0);
}

static inline void
set_result_value(uint32_t result)
{
    uint32_t key = 0;
    bpf_map_update_elem(&result_value_map, &key, &result, 0);
}

static inline void*
get_sample_map(void)
{
    uint32_t key = 0;
    void* map = NULL;

    uint32_t* config = bpf_map_lookup_elem(&config_map, &key);
    if (!config) {
        return NULL;
    }
    if (*config == CONFIG_USE_HASH_MAP) {
        map = &sample_hash_map;
    }
    return map;
}

SEC("sample_ext")
uint32_t
test_map_read_increment(sample_program_context_t* ctx)
{
    void* sample_map = get_sample_map();
    if (!sample_map) {
        set_result(OPERATION_FAILURE);
        return 0;
    }
    uint32_t key = 0;
    uint32_t* value = bpf_map_lookup_elem(sample_map, &key);
    if (value) {
        (*value)++;
    }
    set_result(value ? OPERATION_SUCCESS : OPERATION_FAILURE);
    return 0;
}

SEC("sample_ext")
uint32_t
test_map_read_helper_increment(sample_program_context_t* ctx)
{
    void* sample_map = get_sample_map();
    if (!sample_map) {
        set_result(OPERATION_FAILURE);
        return 0;
    }
    uint32_t key = 0;
    uint32_t* value = sample_ext_helper_map_lookup_element(sample_map, &key);
    if (value) {
        (*value)++;
    }
    set_result(value ? OPERATION_SUCCESS : OPERATION_FAILURE);
    return 0;
}

SEC("sample_ext")
uint32_t
test_map_read_helper_value(sample_program_context_t* ctx)
{
    set_result_value(0);

    void* sample_map = get_sample_map();
    if (!sample_map) {
        set_result(OPERATION_FAILURE);
        return 0;
    }
    uint32_t key = 0;
    uint32_t value = 0;
    int ret = sample_ext_helper_map_get_value(sample_map, &key, (uint8_t*)&value, sizeof(value));
    if (ret == 0) {
        set_result_value(value);
        set_result(OPERATION_SUCCESS);
    } else {
        set_result(OPERATION_FAILURE);
    }

    return 0;
}

SEC("sample_ext")
uint32_t
test_map_read_helper_increment_invalid(sample_program_context_t* ctx)
{
    uint32_t key = 0;
    // Invoke helper on a non-extensible map to test failure case.
    uint32_t* value = sample_ext_helper_map_lookup_element(&array_map, &key);
    if (value) {
        (*value)++;
    }
    set_result(value ? OPERATION_SUCCESS : OPERATION_FAILURE);
    return 0;
}

SEC("sample_ext")
uint32_t
test_map_update_element(sample_program_context_t* ctx)
{
    void* sample_map = get_sample_map();
    if (!sample_map) {
        set_result(OPERATION_FAILURE);
        return 0;
    }
    uint32_t key = 0;
    uint32_t value = 42;
    int result = bpf_map_update_elem(sample_map, &key, &value, 0);
    set_result(result == 0 ? OPERATION_SUCCESS : OPERATION_FAILURE);
    return 0;
}

SEC("sample_ext")
uint32_t
test_map_delete_element(sample_program_context_t* ctx)
{
    void* sample_map = get_sample_map();
    if (!sample_map) {
        set_result(OPERATION_FAILURE);
        return 0;
    }
    uint32_t key = 0;
    int result = bpf_map_delete_elem(sample_map, &key);
    set_result(result == 0 ? OPERATION_SUCCESS : OPERATION_FAILURE);
    return 0;
}

SEC("sample_ext")
uint32_t
test_map_find_and_delete_element(sample_program_context_t* ctx)
{
    void* sample_map = get_sample_map();
    if (!sample_map) {
        set_result(OPERATION_FAILURE);
        return 0;
    }
    uint32_t key = 0;
    uint32_t* value = bpf_map_lookup_and_delete_elem(sample_map, &key);
    set_result(value == NULL ? OPERATION_FAILURE : OPERATION_SUCCESS);
    return 0;
}

SEC("sample_ext")
uint32_t
test_map_push_elem(sample_program_context_t* ctx)
{
    void* sample_map = get_sample_map();
    if (!sample_map) {
        set_result(OPERATION_FAILURE);
        return 0;
    }
    uint32_t value = 100;
    int result = bpf_map_push_elem(sample_map, &value, 0);
    set_result(result == 0 ? OPERATION_SUCCESS : OPERATION_FAILURE);
    return 0;
}

SEC("sample_ext")
uint32_t
test_map_pop_elem(sample_program_context_t* ctx)
{
    void* sample_map = get_sample_map();
    if (!sample_map) {
        set_result(OPERATION_FAILURE);
        return 0;
    }
    uint32_t value = 0;
    int result = bpf_map_pop_elem(sample_map, &value);
    set_result(result == 0 ? OPERATION_SUCCESS : OPERATION_FAILURE);
    return 0;
}

SEC("sample_ext")
uint32_t
test_map_peek_elem(sample_program_context_t* ctx)
{
    void* sample_map = get_sample_map();
    if (!sample_map) {
        set_result(OPERATION_FAILURE);
        return 0;
    }
    uint32_t value = 0;
    int result = bpf_map_peek_elem(sample_map, &value);
    set_result(result == 0 ? OPERATION_SUCCESS : OPERATION_FAILURE);
    return 0;
}