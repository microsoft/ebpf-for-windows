// Copyright (c) eBPF for Windows contributors
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

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

typedef struct _audit_entry
{
    uint64_t logon_id;
    int32_t is_admin;
} audit_entry_t;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, process_entry_t);
    __uint(max_entries, 1024);
} process_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, audit_entry_t);
    __uint(max_entries, 1024);
} audit_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} limits_map SEC(".maps");

inline void
update_audit_entry(bind_md_t* ctx)
{
    uint64_t process_id = bpf_get_current_pid_tgid();
    audit_entry_t audit_entry = {0};

    audit_entry.logon_id = bpf_get_current_logon_id(ctx);
    audit_entry.is_admin = bpf_is_current_admin(ctx);

    bpf_map_update_elem(&audit_map, &process_id, &audit_entry, 0);
}

__attribute__((always_inline)) process_entry_t*
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

    if (memcpy_s(entry->name, sizeof(entry->name), ctx->app_id_start, ctx->app_id_end - ctx->app_id_start) !=
        ctx->app_id_end - ctx->app_id_start) {
        return entry;
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
    uint32_t limit_key = 0;
    process_entry_t* entry;

    update_audit_entry(ctx);

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
