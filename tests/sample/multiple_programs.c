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

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} canary SEC(".maps");

inline void
lookup_canary()
{
    uint32_t key = 0;
    uint32_t* value = bpf_map_lookup_elem(&canary, &key);
    if (value) {
        *value = 1;
    }
}

SEC("bind_2")
int
program3(bind_md_t* ctx)
{
    lookup_canary();
    lookup_canary();
    lookup_canary();
    return 3;
}

SEC("bind_4")
int
program1(bind_md_t* ctx)
{
    lookup_canary();
    return 1;
}

SEC("bind_3")
int
program2(bind_md_t* ctx)
{
    lookup_canary();
    lookup_canary();
    return 2;
}

SEC("bind_1")
int
program4(bind_md_t* ctx)
{
    lookup_canary();
    lookup_canary();
    lookup_canary();
    lookup_canary();
    return 4;
}