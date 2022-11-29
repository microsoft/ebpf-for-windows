// Copyright (c) Microsoft Corporation
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

//
// This native program sets up indirect mutual references between a map and a program, i.e.
//      program1 --> map-of-maps --> program2 --> map --> ... --> program1
//
// The purpose of this program is to ensure that ebpf_core correctly identifies and prohibits the formation of such
// cycles.
//

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

SEC("maps")
struct bpf_map_def prog_array_map = {
    .type = BPF_MAP_TYPE_PROG_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 2};

#if 0
SEC("maps")
struct bpf_map_def process_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(process_entry_t),
    .max_entries = 1024};
#endif

SEC("bind")
int
xref_indirect(bind_md_t* ctx)
{
    int rc = 0;
#if 0
    uint64_t key = ctx->process_id;
    process_entry_t value = {1, "func"};

    rc = bpf_map_update_elem(&process_map, &key, &value, 0);
#endif
    return rc;
}
