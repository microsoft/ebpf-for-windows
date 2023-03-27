// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c invalid_helpers.c -o invalid_helpers.o
//
// For bpf code: clang -target bpf -O2 -Werror -c invalid_helpers.c -o invalid_helpers.o
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

#define INNER_MAP_ID 10

#define INVALID_HELPER_ID 999

static void* (*invalid_helper_function)(void* map, const void* key) = (void*)INVALID_HELPER_ID;

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

SEC("maps")
struct bpf_map_def process_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(process_entry_t),
    .max_entries = 1024};

SEC("maps")
struct bpf_map_def limits_map = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 1};

SEC("maps")
struct bpf_map_def prog_array_map = {
    .type = BPF_MAP_TYPE_PROG_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 2};

SEC("maps")
// Dummy map. Should not be populated by UM.
struct bpf_map_def dummy_map = {
    .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 1000};

SEC("maps")
struct _ebpf_map_definition_in_file dummy_outer_map = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
    // inner_id refers to the id of the inner map in the same ELF object.
    .inner_id = INNER_MAP_ID};

SEC("maps")
struct _ebpf_map_definition_in_file dummy_outer_idx_map = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 10,
    .inner_map_idx = 6};

SEC("maps")
struct _ebpf_map_definition_in_file dummy_inner_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
    .id = INNER_MAP_ID};

inline process_entry_t*
find_or_create_process_entry(bind_md_t* ctx)
{
    uint64_t key = ctx->process_id;
    process_entry_t* entry;
    process_entry_t value = {0};
    int index;

    entry = bpf_map_lookup_elem(&process_map, &key);
    if (entry) {
        return entry;
    }

    entry = invalid_helper_function(&process_map, &key);
    if (entry) {
        return entry;
    }

    if (ctx->operation != BIND_OPERATION_BIND) {
        return entry;
    }

    if (!ctx->app_id_start || !ctx->app_id_end) {
        return entry;
    }

    bpf_map_update_elem(&process_map, &key, &value, 0);
    entry = bpf_map_lookup_elem(&process_map, &key);
    if (!entry) {
        return entry;
    }

    for (index = 0; index < 64; index++) {
        if ((ctx->app_id_start + index) >= ctx->app_id_end) {
            break;
        }

        entry->name[index] = ctx->app_id_start[index];
    }
    return entry;
}

// The following line is optional, but is used to verify
// that the BindMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
bind_hook_t BindMonitor;

SEC("bind")
bind_action_t
BindMonitor(bind_md_t* ctx)
{
    uint32_t dummy_key = 0;
    uint32_t* dummy_value = bpf_map_lookup_elem(&dummy_map, &dummy_key);

    if (!dummy_value) {
        // Callee0 is at index 0
        int index = 0;
        bpf_tail_call(ctx, &prog_array_map, index);
    }

    return BIND_DENY;
}

SEC("bind/0")
bind_action_t
BindMonitor_Callee0(bind_md_t* ctx)
{
    uint32_t dummy_key = 0;
    uint32_t* dummy_value = bpf_map_lookup_elem(&dummy_map, &dummy_key);

    if (!dummy_value) {
        // Callee1 is at index 1
        int index = 1;
        bpf_tail_call(ctx, &prog_array_map, index);
    }

    return BIND_DENY;
}

SEC("bind/1")
bind_action_t
BindMonitor_Callee1(bind_md_t* ctx)
{
    uint32_t limit_key = 0;
    process_entry_t* entry;
    uint32_t* limit = bpf_map_lookup_elem(&limits_map, &limit_key);
    if (!limit || *limit == 0) {
        return BIND_PERMIT;
    }

    entry = find_or_create_process_entry(ctx);

    if (!entry) {
        return BIND_PERMIT;
    }

    switch (ctx->operation) {
    case BIND_OPERATION_BIND:
        if (entry->count >= *limit) {
            return BIND_DENY;
        }

        entry->count++;
        break;
    case BIND_OPERATION_UNBIND:
        if (entry->count > 0) {
            entry->count--;
        }
        break;
    default:
        break;
    }

    if (entry->count == 0) {
        uint64_t key = ctx->process_id;
        bpf_map_delete_elem(&process_map, &key);
    }

    return BIND_PERMIT;
}
