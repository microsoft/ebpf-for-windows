// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief This file contains platform specific defines used by eBPF programs.
 */

#include <stdint.h>

// For eBPF programs, struct bpf_map means struct _ebpf_map_definition_in_file,
// since they use inner_map_idx and pass pointers to such structures to the various
// map APIs.
#define bpf_map _ebpf_map_definition_in_file

// Type aliases used by libbpf headers.
typedef int32_t __s32;
typedef int64_t __s64;
typedef uint16_t __be16;
typedef uint16_t __u16;
typedef uint32_t __be32;
typedef uint32_t __u32;
typedef uint32_t __wsum;
typedef uint64_t __u64;
