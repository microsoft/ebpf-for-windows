// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Test eBPF program for EBPF_PROGRAM_TYPE_SAMPLE implemented in
// the Sample eBPF extension.

#include "sample_common_routines.h"
#include "sample_ext_helpers.h"
#include "sample_test_common.h"

#define VALUE_SIZE 32

SEC("maps")
ebpf_map_definition_in_file_t test_map = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = VALUE_SIZE,
    .max_entries = 2};

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
                if (result < 0)
                    goto Exit;
            }
        }
    }

    result = sample_ebpf_extension_helper_function1(context);
    if (result < 0)
        goto Exit;

    // "The answer to the question of life, the universe and everything".
    //          - Douglas Adams (The Hitchhiker’s Guide to the Galaxy).
    result = 42;
Exit:
    return result;
}

SEC("maps")
struct bpf_map utility_map = {
    .size = sizeof(struct bpf_map),
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(ebpf_utility_helpers_data_t),
    .max_entries = UTILITY_MAP_SIZE};

SEC("sample_ext/utility")
int
test_utility_helpers(sample_program_context_t* context)
{
    return test_utility_helper_functions(&utility_map);
}
