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
#include "ebpf_nethooks.h"

//
// This native program results in direct mutual references between a map and a program, i.e. program --> map --> program
//
// The purpose of this program is to ensure that ebpf_core correctly identifies and prohibits the formation of such
// cycles.
//

SEC("maps")
struct bpf_map_def prog_array_map = {
    .type = BPF_MAP_TYPE_PROG_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 8};

SEC("bind")
bind_action_t
xref_direct_start(bind_md_t* ctx)
{
    int rc = 0;
    uint32_t some_key = 0;
    uint32_t* some_value = 0;
    int index = 0;

    bpf_tail_call(ctx, &prog_array_map, index);

    return BIND_PERMIT;
}

// *FOR NOW*, the (case-sensitive) section names for other ebpf programs here must have the same prefix as the first
// caller (xref_direct_main()), i.e. "bind" in this case. The remainder of the section name string can be anything
// so long as the resulting string is unique.  E.g. Instead of "bind_a", we could have also used "bind/0",
// "bind_first", "bind/first", "bind/a" etc.
//
SEC("bind_a")
bind_action_t
xref_direct_first(bind_md_t* ctx)
{
    int index = 1;

    bpf_tail_call(ctx, &prog_array_map, index);

    return BIND_PERMIT;
}

SEC("bind_b")
bind_action_t
xref_direct_second(bind_md_t* ctx)
{
    return BIND_PERMIT;
}
