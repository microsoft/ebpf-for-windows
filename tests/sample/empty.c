// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c droppacket_unsafe.c -o droppacket_unsafe_jit.o
//
// For bpf code: clang -target bpf -O2 -Werror -c droppacket_unsafe.c -o droppacket_unsafe.o
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

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/ip.h"
#include "net/udp.h"

SEC("maps")
struct bpf_map_def port_map = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint64_t), .max_entries = 1};

// EBPF program with no segments