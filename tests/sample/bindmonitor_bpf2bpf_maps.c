// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c bindmonitor_bpf2bpf_maps.c -o bindmonitor_bpf2bpf_maps.o
//
// For bpf code: clang -target bpf -O2 -Werror -c bindmonitor_bpf2bpf_maps.c -o bindmonitor_bpf2bpf_maps.o
// this passes the checker

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

// This sample tests bpf2bpf (local function) calls where:
// - A subprogram calls helper functions (bpf_get_current_pid_tgid)
// - A subprogram performs map operations (lookup + update)

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, uint64_t);
    __uint(max_entries, 128);
} bind_count_map SEC(".maps");

// Subprogram that calls a helper function and performs map operations.
// It looks up the bind count for the given PID, increments it, and updates the map.
// Returns 0 on success, non-zero on failure.
__attribute__((noinline)) int __attribute__((optnone))
BindMonitor_UpdateMap(uint64_t* pid_ptr)
{
    uint64_t pid = *pid_ptr;

    // Call a helper function to get the current PID/TGID.
    uint64_t pid_tgid = bpf_get_current_pid_tgid();

    // Use pid_tgid to verify the helper was invoked (non-zero means success).
    if (pid_tgid == 0) {
        return -1;
    }

    // Perform map lookup and update.
    uint64_t* count = bpf_map_lookup_elem(&bind_count_map, &pid);
    if (count) {
        uint64_t new_count = *count + 1;
        return bpf_map_update_elem(&bind_count_map, &pid, &new_count, 0);
    } else {
        uint64_t initial_count = 1;
        return bpf_map_update_elem(&bind_count_map, &pid, &initial_count, 0);
    }
}

SEC("bind")
bind_action_t
BindMonitor_MapCallee(bind_md_t* ctx)
{
    uint64_t pid = ctx->process_id;

    // Call subprogram that invokes a helper function and performs map operations.
    int result = BindMonitor_UpdateMap(&pid);

    if (result != 0) {
        return BIND_DENY;
    }

    return BIND_PERMIT_SOFT;
}
