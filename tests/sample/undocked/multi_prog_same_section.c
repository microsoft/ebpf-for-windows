// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Sample program to validate native parsing when multiple top-level programs
// share the same section name.

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

SEC("sample_ext")
int
prog1(sample_program_context_t* ctx)
{
    return 0;
}

SEC("sample_ext")
int
prog2(sample_program_context_t* ctx)
{
    return 1;
}
