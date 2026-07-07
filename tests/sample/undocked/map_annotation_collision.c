// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c map_annotation_collision.c -o map_annotation_collision.o
//
// For bpf code: clang -target bpf -O2 -Werror -c map_annotation_collision.c -o map_annotation_collision.o
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

// This program tests that verifier-assisted map annotations are correctly
// scoped per-program and not shared with BPF-to-BPF subprograms.
//
// The main function performs an array-map lookup, which can get a verifier
// annotation and be inlined by bpf2c. The subprogram also performs a map
// lookup, but on a different map type. If annotations from the main program
// were incorrectly reused for the subprogram at colliding local offsets,
// bpf2c could inline the wrong map in the subprogram path.

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 10);
} array_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 16);
} hash_map SEC(".maps");

__attribute__((noinline)) uint64_t
lookup_hash_value(uint32_t key)
{
    uint64_t* value = bpf_map_lookup_elem(&hash_map, &key);
    if (!value) {
        return 0;
    }
    return *value;
}

SEC("sample_ext")
int
map_annotation_collision(sample_program_context_t* ctx)
{
    (void)ctx;

    uint32_t key = 0;

    uint64_t* array_value = bpf_map_lookup_elem(&array_map, &key);
    if (array_value == NULL) {
        return -1;
    }

    uint64_t hash_value = lookup_hash_value(key);
    return (int)(*array_value + hash_value);
}
