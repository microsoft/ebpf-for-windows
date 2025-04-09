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

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 64 * 1024);
} test_map SEC(".maps");

SEC("sample_ext")
int
test_program_entry(sample_program_context_t* context)
{
    if (context->data_end > context->data_start) {

        size_t app_id_size = context->data_end - context->data_start;
        uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU | (app_id_size << EBPF_MAP_FLAG_CTX_LENGTH_SHIFT);
        (void)bpf_perf_event_output(
            context, &test_map, flags, context->data_start, context->data_end - context->data_start);
    }

    return 0;
}
