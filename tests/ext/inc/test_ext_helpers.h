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

// This file contains APIs for helper functionss that are
// exposed by test extension.

#define TEST_EXT_HELPER_FN_BASE 0xFFFF

typedef int (*test_ebpf_extension_helper_func1_t)(test_program_context_t* context);
#define test_ebpf_extension_helper_func1 ((test_ebpf_extension_helper_func1_t)TEST_EXT_HELPER_FN_BASE + 1)
typedef void (*test_ebpf_extension_helper_func2_t)(void* mem_pointer, uint32_t size);
#define test_ebpf_extension_helper_func2 ((test_ebpf_extension_helper_func2_t)TEST_EXT_HELPER_FN_BASE + 2)
typedef void (*test_ebpf_extension_helper_func3_t)(uint8_t param);
#define test_ebpf_extension_helper_func3 ((test_ebpf_extension_helper_func3_t)TEST_EXT_HELPER_FN_BASE + 3)