// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c callgraph_bpf2bpf.c -o callgraph_bpf2bpf.o
//
// For bpf code: clang -target bpf -O2 -Werror -c callgraph_bpf2bpf.c -o callgraph_bpf2bpf.o

// Scenario coverage:
// - Two entry programs with different numbers of direct helper calls.
// - Four subprograms: S1, S2, S3, S4.
// - S1, S3, S4 each invoke a different helper; S2 invokes no helpers.
// - S1 -> S2 -> S3 call chain.
// - EntryOne invokes S1 and S4.
// - EntryTwo invokes S2.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

bind_action_t
ScenarioS1(uint64_t* pid);

bind_action_t
ScenarioS2(uint64_t* pid);

bind_action_t
ScenarioS3(uint64_t* pid);

bind_action_t
ScenarioS4(uint64_t* pid);

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

SEC("bind")
bind_action_t
ThemeEntryOne(bind_md_t* ctx)
{
    uint64_t pid = ctx->process_id;
    bind_action_t from_s1;
    bind_action_t from_s4;

    // EntryOne directly calls two helpers.
    (void)bpf_get_current_pid_tgid();
    (void)bpf_ktime_get_ns();

    from_s1 = ScenarioS1(&pid);
    from_s4 = ScenarioS4(&pid);

    if (from_s1 == BIND_REDIRECT && from_s4 == BIND_PERMIT_SOFT) {
        return BIND_REDIRECT;
    }
    return BIND_DENY;
}

SEC("bind")
bind_action_t
ThemeEntryTwo(bind_md_t* ctx)
{
    uint64_t pid = ctx->process_id;
    bind_action_t from_s2;

    // EntryTwo directly calls one helper.
    (void)bpf_get_current_pid_tgid();
    // (void)bpf_ktime_get_ns();

    from_s2 = ScenarioS2(&pid);

    if (from_s2 == BIND_REDIRECT) {
        return BIND_PERMIT_SOFT;
    }
    return BIND_DENY;
}
