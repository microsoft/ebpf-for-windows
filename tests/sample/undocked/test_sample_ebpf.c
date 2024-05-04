// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

// Test eBPF program for EBPF_PROGRAM_TYPE_SAMPLE implemented in
// the Sample eBPF extension.

#include "sample_common_routines.h"
#include "sample_ext_helpers.h"
#include "sample_test_common.h"

#define VALUE_SIZE 32

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __uint(value_size, VALUE_SIZE);
    __uint(max_entries, 2);
} test_map SEC(".maps");

SEC("sample_ext")
int
test_program_entry(sample_program_context_t* context)
{
    int64_t result;
    uint32_t keys[2] = {0, 1};
    uint8_t* values[2] = {0};

    values[0] = bpf_map_lookup_elem(&test_map, &keys[0]);
    values[1] = bpf_map_lookup_elem(&test_map, &keys[1]);

    if (context->data_end > context->data_start) {
        int64_t position = 0;

        if (values[0]) {
            position = sample_ebpf_extension_find(
                context->data_start, context->data_end - context->data_start, values[0], VALUE_SIZE);
            if (values[1]) {
                result = sample_ebpf_extension_replace(
                    context->data_start, context->data_end - context->data_start, position, values[1], VALUE_SIZE);
                if (result < 0) {
                    goto Exit;
                }
            }
        }
    }

    result = sample_ebpf_extension_helper_function1(context);
    if (result < 0) {
        goto Exit;
    }

    // "The answer to the question of life, the universe and everything".
    //          - Douglas Adams (The Hitchhiker’s Guide to the Galaxy).
    result = 42;
Exit:
    return result;
}
