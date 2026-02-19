// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test program for perf event array CPU-targeted writes using BPF_F_INDEX_MASK.
// Writes a single event to the perf event array targeting a specific CPU index
// passed via ctx->uint32_data. Returns the result of bpf_perf_event_output.

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 16 * 1024);
} cpu_target_map SEC(".maps");

SEC("sample_ext")
int
perf_event_cpu_target(sample_program_context_t* ctx)
{
    uint8_t* data_start = ctx->data_start;
    uint8_t* data_end = ctx->data_end;

    if (data_start == NULL || data_end == NULL || data_end <= data_start) {
        return -1;
    }

    uint64_t data_size = (uint64_t)(data_end - data_start);
    if (data_size >= ((uint64_t)1 << 30)) {
        return -1;
    }

    // Use ctx->uint32_data as the target CPU index in the low 32 bits of flags.
    uint64_t flags = (uint64_t)ctx->uint32_data;

    return bpf_perf_event_output(ctx, &cpu_target_map, flags, data_start, data_size);
}
