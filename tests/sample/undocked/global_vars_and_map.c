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
#include "sample_ext_helpers.h"

// Declare some configuration struct that will be used in the map and as a global variable.
typedef struct _some_config_struct
{
    int some_config_field;
    int some_other_config_field;
    uint64_t some_config_field_64;
    uint64_t some_other_config_field_64;
} some_config_struct_t;

// Declare a hash-map with a single entry of type some_config_struct_t.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, some_config_struct_t);
    __uint(max_entries, 1);
} some_config_map SEC(".maps");

// Declare a global variable of type some_config_struct_t.
static some_config_struct_t global_config;

SEC("sample_ext")
int
GlobalVariableAndMapTest(sample_program_context_t* ctx)
{
    // Look up the value in the map.
    uint32_t key = 0;
    some_config_struct_t* value = bpf_map_lookup_elem(&some_config_map, &key);
    if (!value) {
        return 1;
    }

    // Update the global variable with the value from the map.
    memcpy((void*)&global_config, value, sizeof(some_config_struct_t));

    return 0;
}
