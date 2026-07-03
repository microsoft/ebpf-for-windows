// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c map_sequential_lookup.c -o map_sequential_lookup.o
//
// For bpf code: clang -target bpf -O2 -Werror -c map_sequential_lookup.c -o map_sequential_lookup.o
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

// Regression test for verifier assign_valid_ptr svalue havoc bug.
//
// This program performs two sequential map_lookup_elem calls on the same
// execution path with a null-check branch between them. If the verifier
// fails to havoc svalue in assign_valid_ptr(), the first lookup's non-null
// branch narrows r0.svalue to [1,+oo], and the second lookup inherits the
// stale svalue constraint. The null branch after the second lookup then
// becomes unreachable (bottom), causing bpf2c to miss the inlining
// annotation for that callsite.
//
// With the fix, both array map lookups should be inlined in the bpf2c
// output. Without the fix, only the first lookup gets inlined.

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 2);
} stats_map SEC(".maps");

SEC("sample_ext")
int
map_sequential_lookup(sample_program_context_t* ctx)
{
    (void)ctx;
    uint32_t key_0 = 0;
    uint32_t key_1 = 1;

    // First array map lookup — verifier annotates this, bpf2c inlines it.
    uint32_t* val_0 = bpf_map_lookup_elem(&stats_map, &key_0);
    if (!val_0) {
        return -1;
    }

    // Second array map lookup on the same path — after the null check above
    // narrowed r0.svalue. The verifier must havoc svalue before assigning
    // the new pointer so this lookup's null branch remains reachable.
    uint32_t* val_1 = bpf_map_lookup_elem(&stats_map, &key_1);
    if (!val_1) {
        return -2;
    }

    return (int)(*val_0 + *val_1);
}
