// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// This file contains data structures that are shared by the sample eBPF programs and the
// corresponding user mode test applications.

#pragma once

#include <stdint.h>

typedef struct _ebpf_utility_helpers_data
{
    uint32_t random;
    uint64_t timestamp;
    uint64_t boot_timestamp;
    uint32_t cpu_id;
    uint64_t pid_tgid;
} ebpf_utility_helpers_data_t;

#define UTILITY_MAP_SIZE 2
#define SAMPLE_EXT_PID_TGID 9999
