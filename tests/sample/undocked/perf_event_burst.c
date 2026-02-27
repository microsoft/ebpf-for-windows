// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test program for perf event array lost-event handling.
// Writes a burst of events to a perf event array map and returns
// the count of failed writes (negative value indicates errors).

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

#define MAX_BURST_COUNT 100000

// Perf event array map for testing lost events.
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 16 * 1024);
} burst_test_map SEC(".maps");

SEC("sample_ext")
int
perf_event_burst(sample_program_context_t* ctx)
{
    // burst_count is passed in ctx->uint32_data field.
    // Data to send is between ctx->data_start and ctx->data_end.
    uint64_t burst_count = (uint64_t)ctx->uint32_data;
    uint8_t* data_start = ctx->data_start;
    uint8_t* data_end = ctx->data_end;

    // Validate data pointers.
    if (data_start == NULL || data_end == NULL || data_end <= data_start) {
        return -1;
    }
    // Limit burst count/data_size for verifier.
    if (burst_count > MAX_BURST_COUNT) {
        return -1;
    }

    // The 2 high bits of the 32-bit record header are flags, so record size is limited to 30 bits (1GB).
    uint64_t data_size = (uint64_t)(data_end - data_start);
    if (data_size >= ((uint64_t)1 << 30)) {
        return -1;
    }

    int failed_writes = 0;
    uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU;

    // Write burst_count events to the perf event array (with the same data).
    for (uint64_t i = 0; i < burst_count; i++) {
        int result = bpf_perf_event_output(ctx, &burst_test_map, flags, data_start, data_size);
        if (result != 0) {
            failed_writes++;
        }
    }

    // Return count of failed writes (0 means all succeeded).
    return failed_writes;
}
