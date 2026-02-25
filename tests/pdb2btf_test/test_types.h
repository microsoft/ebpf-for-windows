// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

// Test types for pdb2btf conversion

#include <stdint.h>

// Enum test
typedef enum _test_enum
{
    TEST_ENUM_VALUE1 = 0,
    TEST_ENUM_VALUE2 = 1,
    TEST_ENUM_VALUE3 = 100
} test_enum_t;

// Struct with various member types
typedef struct _test_struct
{
    uint32_t field1;
    uint64_t field2;
    char field3;
    void* field4;
    test_enum_t field5;
} test_struct_t;

// Struct with bitfields
typedef struct _test_bitfield_struct
{
    uint32_t bit_field1 : 1;
    uint32_t bit_field2 : 3;
    uint32_t bit_field3 : 28;
    uint32_t regular_field;
} test_bitfield_struct_t;

// Union test
typedef union _test_union {
    uint32_t as_uint32;
    uint64_t as_uint64;
    struct
    {
        uint16_t low;
        uint16_t high;
    } as_words;
} test_union_t;

// Array test
typedef struct _test_array_struct
{
    uint32_t array_field[10];
    char string_field[256];
} test_array_struct_t;

// Nested struct test
typedef struct _test_nested_struct
{
    test_struct_t nested;
    test_array_struct_t nested_array;
} test_nested_struct_t;

// Function pointer type
typedef void (*test_function_ptr_t)(test_struct_t* param1, uint32_t param2);

// Function prototype
void test_function(test_struct_t* input, test_nested_struct_t* output);

// Forward declaration
struct forward_declared_struct;

// Typedef to pointer
typedef struct forward_declared_struct* forward_ptr_t;
