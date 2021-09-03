// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// eBPF program for testing utility general helper functions.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"
#include "sample_common_routines.h"
#include "sample_test_common.h"

#define VALUE_SIZE 32

SEC("maps")
struct bpf_map utility_map = {
    .size = sizeof(struct bpf_map),
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(ebpf_utility_helpers_data_t),
    .max_entries = UTILITY_MAP_SIZE};

SEC("xdp")
int
test_utility_helpers(xdp_md_t* context)
{
    return test_utility_helper_functions(&utility_map);
}
