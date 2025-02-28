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

#include "bpf_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 64 * 1024);
} process_map SEC(".maps");

SEC("bind")
bind_action_t
bind_monitor(bind_md_t* ctx)
{
    uint64_t flags = (1ULL << 32) - 1;
    switch (ctx->operation) {
    case BIND_OPERATION_BIND:
        if (ctx->app_id_end > ctx->app_id_start) {
            (void)bpf_perf_event_output(
                ctx, &process_map, flags, ctx->app_id_start, ctx->app_id_end - ctx->app_id_start);
        }
        break;
    default:
        break;
    }

    return BIND_PERMIT;
}
