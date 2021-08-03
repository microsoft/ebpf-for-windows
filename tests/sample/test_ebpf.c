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
                                  .value_size = sizeof(uint64_t),
                                  .max_entries = 128};

#pragma clang section text = "test_ext"
int
test_program_entry(test_program_context_t* context)
{
    test_ebpf_extension_helper_function3(0);
    if (context->data_end > context->data_start) {
        test_ebpf_extension_helper_function2(context->data_start, context->data_end - context->data_start);
    }
    test_ebpf_extension_helper_function1(context);

    // "The answer to the question of life, the universe and everything".
    //          - Douglas Adams (The Hitchhiker’s Guide to the Galaxy).
    return 42;
}
