// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c map_reuse.c -o map_reuse.o
//
// For bpf code: clang -target bpf -O2 -Werror -c map_reuse.c -o map_reuse.o
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

#define FALSE 0
#define TRUE 1

#define DECLARE_MAP(TYPE)                              \
    SEC("maps")                                        \
    struct _ebpf_map_definition_in_file TYPE##_map = { \
        .type = BPF_MAP_TYPE_##TYPE,                   \
        .key_size = sizeof(uint32_t),                  \
        .value_size = sizeof(uint32_t),                \
        .max_entries = 10,                             \
    };

#define DECLARE_MAP_NO_KEY(TYPE)                       \
    SEC("maps")                                        \
    struct _ebpf_map_definition_in_file TYPE##_map = { \
        .type = BPF_MAP_TYPE_##TYPE,                   \
        .key_size = 0,                                 \
        .value_size = sizeof(uint32_t),                \
        .max_entries = 10,                             \
    };

#define TEST_MAP(TYPE, TEST)                                                \
    result = test_##TEST##_map(&TYPE##_map);                                \
    if (result < 0) {                                                       \
        bpf_printk("Test " #TEST " for map " #TYPE " returned %d", result); \
        return result;                                                      \
    }

// General purpose maps
DECLARE_MAP(HASH);
DECLARE_MAP(PERCPU_HASH);
DECLARE_MAP(ARRAY);
DECLARE_MAP(PERCPU_ARRAY);

// LRU
DECLARE_MAP(LRU_HASH);
DECLARE_MAP(LRU_PERCPU_HASH);

// Push/pop maps that have no key
DECLARE_MAP_NO_KEY(QUEUE);
DECLARE_MAP_NO_KEY(STACK);

inline int
test_GENERAL_map(struct _ebpf_map_definition_in_file* map)
{
    uint32_t key = 0;
    uint32_t value = 1;
    uint32_t* return_value = NULL;
    int result = 0;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }

    return_value = bpf_map_lookup_elem(map, &key);
    if (return_value == NULL) {
        bpf_printk("bpf_map_lookup_elem returned NULL");
        return -1;
    }

    result = bpf_map_delete_elem(map, &key);
    if (result < 0) {
        bpf_printk("bpf_map_delete_elem returned %d", result);
        return result;
    }

    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }

    if (map == &ARRAY_map || map == &PERCPU_ARRAY_map) {
        return 0;
    }

    // Find and remove element.
    return_value = bpf_map_lookup_and_delete_elem(map, &key);
    if (return_value == NULL) {
        bpf_printk("bpf_map_lookup_and_delete_elem returned NULL");
        return -1;
    }
    return 0;
}

__attribute__((always_inline)) int
test_LRU_map(struct _ebpf_map_definition_in_file* map)
{
    uint32_t key = 0;
    uint32_t value = 1;
    int result;

    // Insert capacity + 1 entries
#if 0
    for (key = 0; key < 11; key++) {
        result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
        if (result < 0) {
            bpf_printk("bpf_map_update_elem returned %d", result);
            return result;
        }
    }
#else
    // Work around temporary compiler limitation.
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
    key = 1;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
    key = 2;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
    key = 3;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
    key = 4;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
    key = 5;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
    key = 6;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
    key = 7;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
    key = 8;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
    key = 9;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
    key = 10;
    result = bpf_map_update_elem(map, &key, &value, BPF_ANY);
    if (result < 0) {
        bpf_printk("bpf_map_update_elem returned %d", result);
        return result;
    }
#endif
    return 0;
}

#define PUSH_VALUE(MAP, VALUE, REPLACE, EXPECT_RESULT)                                                                \
    {                                                                                                                 \
        uint32_t new_value = VALUE;                                                                                   \
        int result = bpf_map_push_elem(MAP, &new_value, (REPLACE != 0) ? BPF_EXIST : 0);                              \
        if (result != (EXPECT_RESULT)) {                                                                              \
            bpf_printk("bpf_map_push_elem inserting %d expected %d returned %d", new_value, (EXPECT_RESULT), result); \
            return result;                                                                                            \
        }                                                                                                             \
    }

#define POP_VALUE(MAP, EXPECTED_VALUE, EXPECT_RESULT)                                                \
    {                                                                                                \
        uint32_t new_value = 0;                                                                      \
        int result = bpf_map_pop_elem(MAP, &new_value);                                              \
        if ((EXPECT_RESULT) != result) {                                                             \
            bpf_printk("bpf_map_pop_elem expecting result %d returned %d", (EXPECT_RESULT), result); \
            return result;                                                                           \
        } else if (new_value != (EXPECTED_VALUE)) {                                                  \
            bpf_printk("bpf_map_pop_elem return %d expecting %d", new_value, (EXPECTED_VALUE));      \
            return -1;                                                                               \
        }                                                                                            \
    }

#define PEEK_VALUE(MAP, EXPECTED_VALUE, EXPECT_RESULT)                                                \
    {                                                                                                 \
        uint32_t new_value = 0;                                                                       \
        int result = bpf_map_peek_elem(MAP, &new_value);                                              \
        if ((EXPECT_RESULT) != result) {                                                              \
            bpf_printk("bpf_map_peek_elem expecting result %d returned %d", (EXPECT_RESULT), result); \
            return result;                                                                            \
        } else if (new_value != (EXPECTED_VALUE)) {                                                   \
            bpf_printk("bpf_map_peek_elem return %d expecting %d", new_value, (EXPECTED_VALUE));      \
            return -1;                                                                                \
        }                                                                                             \
    }

struct _ebpf_map_definition_in_file STACK_map;

__attribute__((always_inline)) int
test_PUSH_POP_map(struct _ebpf_map_definition_in_file* map)
{
    int i;
    PEEK_VALUE(map, 0, -7);
    POP_VALUE(map, 0, -7);

#if 0
    for (i = 0; i < 10; i++) {
        PUSH_VALUE(map, i, FALSE, 0);
    }
#else
    // Work around current verifier limitation.
    PUSH_VALUE(map, 0, FALSE, 0);
    PUSH_VALUE(map, 1, FALSE, 0);
    PUSH_VALUE(map, 2, FALSE, 0);
    PUSH_VALUE(map, 3, FALSE, 0);
    PUSH_VALUE(map, 4, FALSE, 0);
    PUSH_VALUE(map, 5, FALSE, 0);
    PUSH_VALUE(map, 6, FALSE, 0);
    PUSH_VALUE(map, 7, FALSE, 0);
    PUSH_VALUE(map, 8, FALSE, 0);
    PUSH_VALUE(map, 9, FALSE, 0);
#endif

    PUSH_VALUE(map, 10, FALSE, -29);
    PUSH_VALUE(map, 10, TRUE, 0);

    PEEK_VALUE(map, (map == &STACK_map) ? 10 : 1, 0);

#if 0
    for (i = 0; i < 10; i++) {
        POP_VALUE(map, (map == &STACK_map) ? 10 - i : i + 1, 0);
    }
#else
    // Work around current verifier limitation.
    POP_VALUE(map, (map == &STACK_map) ? 10 - 0 : 0 + 1, 0);
    POP_VALUE(map, (map == &STACK_map) ? 10 - 1 : 1 + 1, 0);
    POP_VALUE(map, (map == &STACK_map) ? 10 - 2 : 2 + 1, 0);
    POP_VALUE(map, (map == &STACK_map) ? 10 - 3 : 3 + 1, 0);
    POP_VALUE(map, (map == &STACK_map) ? 10 - 4 : 4 + 1, 0);
    POP_VALUE(map, (map == &STACK_map) ? 10 - 5 : 5 + 1, 0);
    POP_VALUE(map, (map == &STACK_map) ? 10 - 6 : 6 + 1, 0);
    POP_VALUE(map, (map == &STACK_map) ? 10 - 7 : 7 + 1, 0);
    POP_VALUE(map, (map == &STACK_map) ? 10 - 8 : 8 + 1, 0);
    POP_VALUE(map, (map == &STACK_map) ? 10 - 9 : 9 + 1, 0);
#endif

    PEEK_VALUE(map, 0, -7);
    POP_VALUE(map, 0, -7);

    return 0;
}

SEC("xdp_prog") int test_maps(struct xdp_md* ctx)
{
    int result;
    TEST_MAP(HASH, GENERAL);
    TEST_MAP(PERCPU_HASH, GENERAL);
    TEST_MAP(ARRAY, GENERAL);
    TEST_MAP(PERCPU_ARRAY, GENERAL);
    TEST_MAP(LRU_HASH, GENERAL);
    TEST_MAP(LRU_PERCPU_HASH, GENERAL);

    TEST_MAP(LRU_HASH, LRU);
    TEST_MAP(LRU_PERCPU_HASH, LRU);

    TEST_MAP(QUEUE, PUSH_POP);
    TEST_MAP(STACK, PUSH_POP);
    return 0;
}
