// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "test_types.h"

void
test_function(test_struct_t* input, test_nested_struct_t* output)
{
    if (input && output) {
        output->nested = *input;
    }
}
