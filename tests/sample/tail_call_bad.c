// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// All of this file is cross-platform except the following
// two includes.  TODO(issue #426): make the include filename(s) also be
// cross-platform for eBPF program portability.
#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"

__attribute__((section("maps"), used)) struct bpf_map map = {
    sizeof(struct bpf_map), BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

__attribute__((section("maps"), used)) struct bpf_map canary = {
    sizeof(struct bpf_map), BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

__attribute__((section("xdp_prog"), used)) int
caller(struct xdp_md* ctx)
{
    uint32_t key = 0;
    uint32_t* value;

    // This should fail since the index is past the end of the array.
    long error = bpf_tail_call(ctx, &map, 1);

    value = bpf_map_lookup_elem(&canary, &key);
    if (value) {
        *value = 1;
    }

    return (int)error;
}

__attribute__((section("xdp_prog/0"), used)) int
callee(struct xdp_md* ctx)
{
    return 42;
}
