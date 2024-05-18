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

// Test eBPF program for EBPF_PROGRAM_TYPE_SAMPLE implemented in
// the Sample eBPF extension.

#include "sample_common_routines.h"
#include "sample_ext_helpers.h"
#include "sample_test_common.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __uint(value_size, sizeof(uint16_t));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} output_map1 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 1);
} output_map2 SEC(".maps");

inline int32_t
update_output_maps(sample_program_context_t* context)
{
    int32_t result;
    uint32_t key = 0;
    uint32_t value1 = context->uint16_data;
    uint32_t value2 = context->uint32_data;

    result = bpf_map_update_elem(&output_map1, &key, &value1, BPF_ANY);
    if (result < 0) {
        goto Exit;
    }
    result = bpf_map_update_elem(&output_map2, &key, &value2, BPF_ANY);

Exit:
    return result;
}

SEC("sample_ext")
int
test_program_entry(sample_program_context_t* context)
{
    int64_t result;
    uint32_t keys[2] = {0, 1};
    uint8_t* values[2] = {0};

    return update_output_maps(context);
}
