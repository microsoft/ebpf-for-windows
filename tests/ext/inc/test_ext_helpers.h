// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

// Test Extension Hook program context.
typedef struct _test_program_context
{
    uint8_t* data_start;
    uint8_t* data_end;
    uint32_t uint32_data;
    uint16_t uint16_data;
} test_program_context_t;

// This file contains APIs for helper functions that are
// exposed by the test extension.

#define TEST_EXT_HELPER_FN_BASE 0xFFFF

typedef int (*test_ebpf_extension_helper_function1_t)(test_program_context_t* context);
#define test_ebpf_extension_helper_function1 ((test_ebpf_extension_helper_function1_t)TEST_EXT_HELPER_FN_BASE + 1)
typedef void (*test_ebpf_extension_helper_function2_t)(void* memory_pointer, uint32_t size);
#define test_ebpf_extension_helper_function2 ((test_ebpf_extension_helper_function2_t)TEST_EXT_HELPER_FN_BASE + 2)
typedef void (*test_ebpf_extension_helper_function3_t)(uint8_t arg);
#define test_ebpf_extension_helper_function3 ((test_ebpf_extension_helper_function3_t)TEST_EXT_HELPER_FN_BASE + 3)