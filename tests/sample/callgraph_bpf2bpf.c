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

// Scenario coverage:
// - Three entry programs in different sections.
// - Four subprograms for helper call graphs: S1, S2, S3, S4.
//   - S1 and S3 invoke bpf_get_current_pid_tgid; S4 invokes bpf_ktime_get_ns; S2 invokes no helpers.
//   - S1 -> S2 -> S3 call chain.
//   - entry_program1 invokes S1 and S4.
//   - entry_program2 invokes S2.
// - One subprogram for map operations: update_map.
//   - Calls bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_map_update_elem.
//   - entry_program3 invokes update_map.

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

// Return value constants.
#define RESULT_REDIRECT 2
#define RESULT_PERMIT 1
#define RESULT_DENY 0

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, uint64_t);
    __uint(max_entries, 128);
} call_count_map SEC(".maps");

int ScenarioS1(uint64_t* pid);
int ScenarioS2(uint64_t* pid);
int ScenarioS3(uint64_t* pid);
int ScenarioS4(uint64_t* pid);
int update_map(uint64_t* pid_ptr);

__attribute__((noinline)) int __attribute__((optnone))
ScenarioS3(uint64_t* pid)
{
    // S3 helper: get current pid/tgid.
    (void)bpf_get_current_pid_tgid();

    // Return based on caller-provided state so this function is not a compile-time constant.
    if (*pid != 0) {
        return RESULT_REDIRECT;
    }
    return RESULT_PERMIT;
}

__attribute__((noinline)) int __attribute__((optnone))
ScenarioS2(uint64_t* pid)
{
    // S2 intentionally uses no helpers.
    return ScenarioS3(pid);
}

__attribute__((noinline)) int __attribute__((optnone))
ScenarioS1(uint64_t* pid)
{
    // S1 helper: get current pid/tgid.
    (void)bpf_get_current_pid_tgid();
    return ScenarioS2(pid);
}

__attribute__((noinline)) int __attribute__((optnone))
ScenarioS4(uint64_t* pid)
{
    (void)pid;

    // S4 helper: monotonic clock.
    (void)bpf_ktime_get_ns();
    return RESULT_PERMIT;
}

// Subprogram that performs map operations.
// It looks up the call count for the given PID, increments it, and updates the map.
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
    uint64_t* count = bpf_map_lookup_elem(&call_count_map, &pid);
    if (count) {
        uint64_t new_count = *count + 1;
        return bpf_map_update_elem(&call_count_map, &pid, &new_count, 0);
    } else {
        uint64_t initial_count = 1;
        return bpf_map_update_elem(&call_count_map, &pid, &initial_count, 0);
    }
}

// entry_program1: calls S1 and S4.
// S1 -> S2 -> S3 chain returns RESULT_REDIRECT (pid is non-zero from context).
// S4 returns RESULT_PERMIT.
// Expected return: RESULT_REDIRECT (2).
SEC("sample_ext/1")
int
entry_program1(sample_program_context_t* ctx)
{
    uint64_t pid = (uint64_t)ctx->uint32_data;
    if (pid == 0) {
        pid = 1;
    }

    // entry_program1 directly calls two helpers.
    (void)bpf_get_current_pid_tgid();
    (void)bpf_ktime_get_ns();

    int from_s1 = ScenarioS1(&pid);
    int from_s4 = ScenarioS4(&pid);

    if (from_s1 == RESULT_REDIRECT && from_s4 == RESULT_PERMIT) {
        return RESULT_REDIRECT;
    }
    return RESULT_DENY;
}

// entry_program2: calls S2 -> S3 chain.
// S3 returns RESULT_REDIRECT (pid is non-zero).
// Expected return: RESULT_PERMIT (1).
SEC("sample_ext/2")
int
entry_program2(sample_program_context_t* ctx)
{
    uint64_t pid = (uint64_t)ctx->uint32_data;
    if (pid == 0) {
        pid = 1;
    }

    // entry_program2 directly calls one helper.
    (void)bpf_get_current_pid_tgid();

    int from_s2 = ScenarioS2(&pid);

    if (from_s2 == RESULT_REDIRECT) {
        return RESULT_PERMIT;
    }
    return RESULT_DENY;
}

// entry_program3: calls update_map subprogram.
// Expected return: RESULT_PERMIT (1) on success.
SEC("sample_ext/3")
int
entry_program3(sample_program_context_t* ctx)
{
    uint64_t pid = (uint64_t)ctx->uint32_data;
    if (pid == 0) {
        pid = 1;
    }

    // Call subprogram that invokes a helper function and performs map operations.
    int result = update_map(&pid);

    if (result != 0) {
        return RESULT_DENY;
    }

    return RESULT_PERMIT;
}
