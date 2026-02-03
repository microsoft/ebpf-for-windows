// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Test program for perf event array lost-event handling.
// Writes a burst of events to a perf event array map and returns
// the count of failed writes (negative value indicates errors).

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

// Perf event array map for testing lost events.
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 16 * 1024);
} burst_test_map SEC(".maps");

SEC("bind")
int
perf_event_burst(bind_md_t* ctx)
{
    // burst_count is passed in ctx->process_id field.
    // Data to send is between ctx->app_id_start and ctx->app_id_end.
    uint64_t burst_count = ctx->process_id;
    uint8_t* data_start = ctx->app_id_start;
    uint8_t* data_end = ctx->app_id_end;

    // Validate data pointers.
    if (data_start == NULL || data_end == NULL || data_end <= data_start) {
        return -1;
    }
    // Limit burst count/data_size for verifier.
    if (burst_count > 100000) {
        return -1;
    }

    // 32-bit record header has 2 flags, so limit data size to 1GB.
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
