// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// All of this file is cross-platform except the following
// two includes.  TODO: make the include filename(s) also be
// cross-platform for eBPF program portability.
#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"

__attribute__((section("maps"), used)) struct bpf_map map = {
    sizeof(struct bpf_map), BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

__attribute__((section("xdp_prog"), used)) int
caller(struct xdp_md* ctx)
{
    // This should fail since the index is past the end of the array.
    long error = bpf_tail_call(ctx, &map, 1);

    return (int)error;
}

__attribute__((section("xdp_prog/0"), used)) int
callee(struct xdp_md* ctx)
{
    return 42;
}
