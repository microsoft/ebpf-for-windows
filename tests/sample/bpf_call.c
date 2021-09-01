// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"

SEC("maps") struct bpf_map map = {sizeof(struct bpf_map), BPF_MAP_TYPE_ARRAY, 2, 4, 512};

SEC("xdp_prog") int func(struct xdp_md* ctx)
{
    uint32_t key = 0;
    uint32_t value = 42;
    int result = bpf_map_update_elem(&map, &key, &value, 0);
    return result;
}
