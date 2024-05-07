// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c invalid_maps3.c -o invalid_maps3.o
//
// For bpf code: clang -target bpf -O2 -Werror -c invalid_maps3.c -o invalid_maps3.o
// this passes the checker

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

// This invalid program creates a map with invalid pinning id.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

#define INNER_MAP_ID 10
#define INVALID_MAP_ID 11

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

#define PIN_TYPE_INVALID 10

SEC("maps")
struct bpf_map_def process_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1024,
    .pinning = PIN_TYPE_INVALID};

// The following line is optional, but is used to verify
// that the BindMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
bind_hook_t BindMonitor;

SEC("bind")
bind_action_t
BindMonitor(bind_md_t* ctx)
{
    return BIND_PERMIT;
}
