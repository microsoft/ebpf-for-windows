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

// Sample program demonstrating the bind hook under BPF_PROG_TYPE_CGROUP_SOCK_ADDR.
// Uses the standard `cgroup/bind4` and `cgroup/bind6` SEC names, with the
// bpf_sock_addr_t context.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

// Map of (port, protocol) tuples to a sock_addr verdict.
typedef struct _bind_verdict_key
{
    uint16_t port;    ///< Local port being bound to (network byte order).
    uint8_t protocol; ///< IP protocol (e.g., IPPROTO_TCP).
    uint8_t pad;
} bind_verdict_key_t;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, bind_verdict_key_t);
    __type(value, uint32_t);
    __uint(max_entries, 256);
} bind_verdict_map SEC(".maps");

// Per-module invocation count used by multi-attach ordering tests.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} bind_invocation_count_map SEC(".maps");

__inline int
authorize_bind(bpf_sock_addr_t* ctx)
{
    bind_verdict_key_t key = {0};
    key.port = (uint16_t)ctx->user_port;
    key.protocol = (uint8_t)ctx->protocol;

    uint32_t* verdict = bpf_map_lookup_elem(&bind_verdict_map, &key);
    if (verdict != NULL) {
        uint32_t invocation_key = 0;
        uint64_t* invocation_count = bpf_map_lookup_elem(&bind_invocation_count_map, &invocation_key);
        if (invocation_count != NULL) {
            (*invocation_count)++;
        }
        return *verdict;
    }
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

SEC("cgroup/bind4")
int
authorize_bind4(bpf_sock_addr_t* ctx)
{
    return authorize_bind(ctx);
}

SEC("cgroup/bind6")
int
authorize_bind6(bpf_sock_addr_t* ctx)
{
    return authorize_bind(ctx);
}
