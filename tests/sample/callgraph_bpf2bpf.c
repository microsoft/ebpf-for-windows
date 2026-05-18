// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c callgraph_bpf2bpf.c -o callgraph_bpf2bpf.o
//
// For bpf code: clang -target bpf -O2 -Werror -c callgraph_bpf2bpf.c -o callgraph_bpf2bpf.o

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

// Scenario coverage:
// - Three entry programs in different sections.
// - Four subprograms for helper call graphs: S1, S2, S3, S4.
//   - S1, S3, S4 each invoke a different helper; S2 invokes no helpers.
//   - S1 -> S2 -> S3 call chain.
//   - entry_program1 invokes S1 and S4.
//   - entry_program2 invokes S2.
// - One subprogram for map operations: update_map.
//   - Calls bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_map_update_elem.
//   - entry_program3 invokes update_map.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, uint64_t);
    __uint(max_entries, 128);
} bind_count_map SEC(".maps");

bind_action_t
ScenarioS1(uint64_t* pid);

bind_action_t
ScenarioS2(uint64_t* pid);

bind_action_t
ScenarioS3(uint64_t* pid);

bind_action_t
ScenarioS4(uint64_t* pid);

int
update_map(uint64_t* pid_ptr);

__attribute__((noinline)) bind_action_t __attribute__((optnone))
ScenarioS3(uint64_t* pid)
{
    // S3 helper: get current pid/tgid.
    (void)bpf_get_current_pid_tgid();

    // Return based on caller-provided state so this function is not a compile-time constant.
    if (*pid != 0) {
        return BIND_REDIRECT;
    }
    return BIND_PERMIT_SOFT;
}

__attribute__((noinline)) bind_action_t __attribute__((optnone))
ScenarioS2(uint64_t* pid)
{
    // S2 intentionally uses no helpers.
    return ScenarioS3(pid);
}

__attribute__((noinline)) bind_action_t __attribute__((optnone))
ScenarioS1(uint64_t* pid)
{
    // S1 helper: get current pid/tgid.
    (void)bpf_get_current_pid_tgid();
    return ScenarioS2(pid);
}

__attribute__((noinline)) bind_action_t __attribute__((optnone))
ScenarioS4(uint64_t* pid)
{
    (void)pid;

    // S4 helper: monotonic clock.
    (void)bpf_ktime_get_ns();
    return BIND_PERMIT_SOFT;
}

// Subprogram that calls a helper function and performs map operations.
// It looks up the bind count for the given PID, increments it, and updates the map.
// Returns 0 on success, non-zero on failure.
__attribute__((noinline)) int __attribute__((optnone))
update_map(uint64_t* pid_ptr)
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

SEC("bind/1")
bind_action_t
entry_program1(bind_md_t* ctx)
{
    uint64_t pid = ctx->process_id;
    bind_action_t from_s1;
    bind_action_t from_s4;

    // entry_program1 directly calls two helpers.
    (void)bpf_get_current_pid_tgid();
    (void)bpf_ktime_get_ns();

    from_s1 = ScenarioS1(&pid);
    from_s4 = ScenarioS4(&pid);

    if (from_s1 == BIND_REDIRECT && from_s4 == BIND_PERMIT_SOFT) {
        return BIND_REDIRECT;
    }
    return BIND_DENY;
}

SEC("bind/2")
bind_action_t
entry_program2(bind_md_t* ctx)
{
    uint64_t pid = ctx->process_id;
    bind_action_t from_s2;

    // entry_program2 directly calls one helper.
    (void)bpf_get_current_pid_tgid();

    from_s2 = ScenarioS2(&pid);

    if (from_s2 == BIND_REDIRECT) {
        return BIND_PERMIT_SOFT;
    }
    return BIND_DENY;
}

SEC("bind/3")
bind_action_t
entry_program3(bind_md_t* ctx)
{
    uint64_t pid = ctx->process_id;

    // Call subprogram that invokes a helper function and performs map operations.
    int result = update_map(&pid);

    if (result != 0) {
        return BIND_DENY;
    }

    return BIND_PERMIT_SOFT;
}
