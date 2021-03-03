// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

// This file contains eBPF definitions needed by eBPF programs as well as
// the verifier and execution context.

typedef enum _ebpf_map_type {
    EBPF_MAP_TYPE_UNSPECIFIED = 0,
    EBPF_MAP_TYPE_HASH = 1,
    EBPF_MAP_TYPE_ARRAY = 2,
} ebpf_map_type_t;

typedef enum ebpf_program_type {
    EBPF_PROGRAM_TYPE_UNSPECIFIED = 0,
    EBPF_PROGRAM_TYPE_XDP = 1,
    EBPF_PROGRAM_TYPE_BIND = 2
} ebpf_program_type_t;
