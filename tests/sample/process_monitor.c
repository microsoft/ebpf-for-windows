// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c bindmonitor.c -o bindmonitor_jit.o
//
// For bpf code: clang -target bpf -O2 -Werror -c bindmonitor.c -o bindmonitor.o
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

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

// The non variable fields from the process_md_t struct.
typedef struct
{
    uint64_t process_id;
    uint64_t parent_process_id;
    uint64_t creating_process_id;
    uint64_t creating_thread_id;
    uint64_t operation;
} process_info_t;

#define MAX_PATH (496 - sizeof(process_info_t))

// LRU hash for storing the image path of a process.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, uint64_t);
    __type(value, char[MAX_PATH]);
    __uint(max_entries, 1024);
} process_map SEC(".maps");

// LRU hash for storing the command line of a process.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, uint64_t);
    __type(value, char[MAX_PATH]);
    __uint(max_entries, 1024);
} command_map SEC(".maps");

// Ring-buffer for process_info_t.
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 64);
} process_ringbuf SEC(".maps");

// The following line is optional, but is used to verify
// that the ProcesMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
process_hook_t ProcesMonitor;

SEC("process")
int
ProcessMonitor(process_md_t* ctx)
{
    process_info_t process_info = {
        .process_id = ctx->process_id,
        .parent_process_id = ctx->parent_process_id,
        .creating_process_id = ctx->creating_process_id,
        .creating_thread_id = ctx->creating_thread_id,
        .operation = ctx->operation,
    };

    if (ctx->operation == PROCESS_OPERATION_CREATE) {
        uint8_t buffer[MAX_PATH];

        memset(buffer, sizeof(buffer), 0);

        memcpy_s(buffer, sizeof(buffer), ctx->command_start, ctx->command_end - ctx->command_start);
        bpf_map_update_elem(&command_map, &process_info.process_id, buffer, BPF_ANY);

        // Reset the buffer.
        memset(buffer, sizeof(buffer), 0);

        // Copy image path into the LRU hash.
        bpf_process_get_image_path(ctx, buffer, sizeof(buffer));
        bpf_map_update_elem(&process_map, &process_info.process_id, buffer, BPF_ANY);
    }
    bpf_ringbuf_output(&process_ringbuf, &process_info, sizeof(process_info), 0);
    return 0;
}
