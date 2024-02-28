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

typedef struct
{
    uint64_t parent_process_id;
    uint8_t command_line[256];
} proces_entry_t;

typedef struct
{
    uint64_t process_id;
    proces_entry_t entry;
} process_create_event_t;

typedef struct
{
    uint64_t process_id;
} process_delete_event_t;

// Map for running processes.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, proces_entry_t);
    __uint(max_entries, 1024);
} process_map SEC(".maps");

// Ringbuffer for process events.
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 64);
} process_ringbuf SEC(".maps");

// For debug builds, limit the number of iterations in the loop to 16 to prevent the verifier from
// running for too long. For release builds, limit the number of iterations to 256.
#if defined(NDEBUG)
#define BOUNDED_MEMCPY_LIMIT 256
#else
#define BOUNDED_MEMCPY_LIMIT 16
#endif

__attribute__((always_inline))
// Copy the first 'source_size' bytes from 'source' to 'destination' and bound the copy to 'destination_size' bytes.
void
bounded_memcpy(uint8_t* destination, const uint8_t* source, uint32_t destination_size, uint32_t source_size)
{
// Prevail verifier doesn't correctly compute the number of iterations in the loop.
// Unroll the loop to avoid the verifier error.
// Issue: https://github.com/vbpf/ebpf-verifier/issues/441
#pragma unroll
    for (uint32_t index = 0; index < BOUNDED_MEMCPY_LIMIT; index++) {
        if (index < destination_size && index < source_size) {
            destination[index] = source[index];
        }
    }
}

// The following line is optional, but is used to verify
// that the ProcesMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
process_hook_t ProcesMonitor;

SEC("process")
int
ProcessMonitor(process_md_t* ctx)
{
    if (ctx->operation == PROCESS_OPERATION_CREATE) {
        process_create_event_t create_event;
        __builtin_memset(&create_event, 0, sizeof(create_event));
        create_event.entry.parent_process_id = ctx->parent_process_id;
        create_event.process_id = ctx->process_id;
        uint64_t process_id = ctx->process_id;

        bounded_memcpy(
            create_event.entry.command_line,
            ctx->command_start,
            sizeof(create_event.entry.command_line),
            (uint32_t)(ctx->command_end - ctx->command_start));

        bpf_map_update_elem(&process_map, &process_id, &create_event.entry, BPF_ANY);
        bpf_ringbuf_output(&process_ringbuf, &create_event, sizeof(create_event), 0);
    } else if (ctx->operation == PROCESS_OPERATION_DELETE) {
        process_delete_event_t delete_event = {.process_id = ctx->process_id};
        uint64_t process_id = ctx->process_id;
        bpf_map_delete_elem(&process_map, &process_id);
        bpf_ringbuf_output(&process_ringbuf, &delete_event, sizeof(delete_event), 0);
    }
    return 0;
}
