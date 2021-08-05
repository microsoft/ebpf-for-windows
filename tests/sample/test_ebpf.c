// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Test eBPF program for EBPF_PROGRAM_TYPE_TEST implemented in
// the Test eBPF extension.

#include "ebpf_helpers.h"
#include "test_ext_helpers.h"

#pragma clang section data = "maps"
ebpf_map_definition_t test_map = {.size = sizeof(ebpf_map_definition_t),
                                  .type = BPF_MAP_TYPE_ARRAY,
                                  .key_size = sizeof(uint32_t),
                                  .value_size = 32,
                                  .max_entries = 2};

#pragma clang section text = "test_ext"
int
test_program_entry(test_program_context_t* context)
{
    uint32_t keys[2] = {0, 1};
    uint8_t* values[2] = {0};
    values[0] = bpf_map_lookup_elem(&test_map, &keys[0]);
    values[1] = bpf_map_lookup_elem(&test_map, &keys[1]);
    test_ebpf_extension_helper_function3(0);
    if (context->data_end > context->data_start) {
        int position;
        int result;
        test_ebpf_extension_helper_function2(context->data_start, context->data_end - context->data_start);
        if (values[0])
            position =
                test_ebpf_extension_find(context->data_start, context->data_end - context->data_start, values[0], 32);
        if (values[1])
            result = test_ebpf_extension_replace(
                context->data_start, context->data_end - context->data_start, position, values[1], 32);
    }
    test_ebpf_extension_helper_function1(context);

    // "The answer to the question of life, the universe and everything".
    //          - Douglas Adams (The Hitchhiker’s Guide to the Galaxy).
    return 42;
}
