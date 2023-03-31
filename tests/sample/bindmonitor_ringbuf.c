// Copyright (c) Microsoft Corporation
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

SEC("maps")
struct bpf_map_def process_map = {.type = BPF_MAP_TYPE_RINGBUF, .max_entries = 256 * 1024};

SEC("bind")
bind_action_t
bind_monitor(bind_md_t* ctx)
{
    switch (ctx->operation) {
    case BIND_OPERATION_BIND:
        if (ctx->app_id_end > ctx->app_id_start) {
            (void)bpf_ringbuf_output(&process_map, ctx->app_id_start, ctx->app_id_end - ctx->app_id_start, 0);
        }
        break;
    default:
        break;
    }

    return BIND_PERMIT;
}
