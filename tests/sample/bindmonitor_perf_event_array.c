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
    size_t ctx_data_len = ctx->app_id_end - ctx->app_id_start;
    uint64_t flags =
        EBPF_MAP_FLAG_CURRENT_CPU | ((ctx_data_len << EBPF_MAP_FLAG_CTXLEN_SHIFT) & EBPF_MAP_FLAG_CTXLEN_MASK);
    uint32_t value = bpf_get_prandom_u32();
    switch (ctx->operation) {
    case BIND_OPERATION_BIND:
        if (ctx->app_id_end > ctx->app_id_start) {
            (void)bpf_perf_event_output(ctx, &process_map, flags, &value, sizeof(value));
        }
        break;
    default:
        break;
    }

    return BIND_PERMIT;
}
