// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// All of this file is cross-platform except the following
// two includes.  TODO: make the include filename(s) also be
// cross-platform for eBPF program portability.
#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"

__attribute__((section("maps"), used)) struct bpf_map map = {sizeof(struct bpf_map), BPF_MAP_TYPE_ARRAY, 2, 4, 512};

__attribute__((section("xdp_prog"), used)) int
func(struct xdp_md* ctx)
{
    uint32_t key = 0;
    uint32_t value = 42;
    int result = bpf_map_update_elem(&map, &key, &value, 0);
    return result;
}
