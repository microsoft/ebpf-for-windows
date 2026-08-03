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
    uint64_t boot_timestamp_ms;
    uint64_t timestamp_ms;
} ebpf_utility_helpers_data_t;

typedef struct _helper_values
{
    uint64_t value_1;
    uint64_t value_2;
} helper_values_t;

#define UTILITY_MAP_SIZE 2
#define SAMPLE_EXT_PID_TGID 9999

// Shared by the process_start_key / thread_start_time sample programs and the api_test
// socket tests. SOCKET_TEST_PORT is the destination port used by the api_test send_traffic()
// helper (and matched by the sample programs); the value structs are the map value layouts the
// sample programs write and api_test reads back.
#define SOCKET_TEST_PORT 0x3bbf

typedef struct _process_start_key_value
{
    uint32_t current_pid;
    uint64_t start_key;
} process_start_key_value_t;

typedef struct _thread_start_time_value
{
    uint32_t current_tid;
    int64_t start_time;
} thread_start_time_value_t;
