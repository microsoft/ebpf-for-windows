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

SEC("maps")
struct bpf_map_def process_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(process_entry_t),
    .max_entries = 1024};

SEC("maps")
struct bpf_map_def audit_map = {
    .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(uint64_t), .value_size = sizeof(audit_entry_t), .max_entries = 1024};

SEC("maps")
struct bpf_map_def limits_map = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 1};

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

#if 0
    for (index = 0; index < 64; index++) {
        if ((ctx->app_id_start + index) >= ctx->app_id_end) {
            break;
        }

        entry->name[index] = ctx->app_id_start[index];
    }
#else
    // Work around temporary verifier limitation.
    if (ctx->app_id_end - ctx->app_id_start > 0) {
        entry->name[0] = ctx->app_id_start[0];
    }
    if (ctx->app_id_end - ctx->app_id_start > 1) {
        entry->name[1] = ctx->app_id_start[1];
    }
    if (ctx->app_id_end - ctx->app_id_start > 2) {
        entry->name[2] = ctx->app_id_start[2];
    }
    if (ctx->app_id_end - ctx->app_id_start > 3) {
        entry->name[3] = ctx->app_id_start[3];
    }
    if (ctx->app_id_end - ctx->app_id_start > 4) {
        entry->name[4] = ctx->app_id_start[4];
    }
    if (ctx->app_id_end - ctx->app_id_start > 5) {
        entry->name[5] = ctx->app_id_start[5];
    }
    if (ctx->app_id_end - ctx->app_id_start > 6) {
        entry->name[6] = ctx->app_id_start[6];
    }
    if (ctx->app_id_end - ctx->app_id_start > 7) {
        entry->name[7] = ctx->app_id_start[7];
    }
    if (ctx->app_id_end - ctx->app_id_start > 8) {
        entry->name[8] = ctx->app_id_start[8];
    }
    if (ctx->app_id_end - ctx->app_id_start > 9) {
        entry->name[9] = ctx->app_id_start[9];
    }
    if (ctx->app_id_end - ctx->app_id_start > 10) {
        entry->name[10] = ctx->app_id_start[10];
    }
    if (ctx->app_id_end - ctx->app_id_start > 11) {
        entry->name[11] = ctx->app_id_start[11];
    }
    if (ctx->app_id_end - ctx->app_id_start > 12) {
        entry->name[12] = ctx->app_id_start[12];
    }
    if (ctx->app_id_end - ctx->app_id_start > 13) {
        entry->name[13] = ctx->app_id_start[13];
    }
    if (ctx->app_id_end - ctx->app_id_start > 14) {
        entry->name[14] = ctx->app_id_start[14];
    }
    if (ctx->app_id_end - ctx->app_id_start > 15) {
        entry->name[15] = ctx->app_id_start[15];
    }
    if (ctx->app_id_end - ctx->app_id_start > 16) {
        entry->name[16] = ctx->app_id_start[16];
    }
    if (ctx->app_id_end - ctx->app_id_start > 17) {
        entry->name[17] = ctx->app_id_start[17];
    }
    if (ctx->app_id_end - ctx->app_id_start > 18) {
        entry->name[18] = ctx->app_id_start[18];
    }
    if (ctx->app_id_end - ctx->app_id_start > 19) {
        entry->name[19] = ctx->app_id_start[19];
    }
    if (ctx->app_id_end - ctx->app_id_start > 20) {
        entry->name[20] = ctx->app_id_start[20];
    }
    if (ctx->app_id_end - ctx->app_id_start > 21) {
        entry->name[21] = ctx->app_id_start[21];
    }
    if (ctx->app_id_end - ctx->app_id_start > 22) {
        entry->name[22] = ctx->app_id_start[22];
    }
    if (ctx->app_id_end - ctx->app_id_start > 23) {
        entry->name[23] = ctx->app_id_start[23];
    }
    if (ctx->app_id_end - ctx->app_id_start > 24) {
        entry->name[24] = ctx->app_id_start[24];
    }
    if (ctx->app_id_end - ctx->app_id_start > 25) {
        entry->name[25] = ctx->app_id_start[25];
    }
    if (ctx->app_id_end - ctx->app_id_start > 26) {
        entry->name[26] = ctx->app_id_start[26];
    }
    if (ctx->app_id_end - ctx->app_id_start > 27) {
        entry->name[27] = ctx->app_id_start[27];
    }
    if (ctx->app_id_end - ctx->app_id_start > 28) {
        entry->name[28] = ctx->app_id_start[28];
    }
    if (ctx->app_id_end - ctx->app_id_start > 29) {
        entry->name[29] = ctx->app_id_start[29];
    }
    if (ctx->app_id_end - ctx->app_id_start > 30) {
        entry->name[30] = ctx->app_id_start[30];
    }
    if (ctx->app_id_end - ctx->app_id_start > 31) {
        entry->name[31] = ctx->app_id_start[31];
    }
    if (ctx->app_id_end - ctx->app_id_start > 32) {
        entry->name[32] = ctx->app_id_start[32];
    }
    if (ctx->app_id_end - ctx->app_id_start > 33) {
        entry->name[33] = ctx->app_id_start[33];
    }
    if (ctx->app_id_end - ctx->app_id_start > 34) {
        entry->name[34] = ctx->app_id_start[34];
    }
    if (ctx->app_id_end - ctx->app_id_start > 35) {
        entry->name[35] = ctx->app_id_start[35];
    }
    if (ctx->app_id_end - ctx->app_id_start > 36) {
        entry->name[36] = ctx->app_id_start[36];
    }
    if (ctx->app_id_end - ctx->app_id_start > 37) {
        entry->name[37] = ctx->app_id_start[37];
    }
    if (ctx->app_id_end - ctx->app_id_start > 38) {
        entry->name[38] = ctx->app_id_start[38];
    }
    if (ctx->app_id_end - ctx->app_id_start > 39) {
        entry->name[39] = ctx->app_id_start[39];
    }
    if (ctx->app_id_end - ctx->app_id_start > 40) {
        entry->name[40] = ctx->app_id_start[40];
    }
    if (ctx->app_id_end - ctx->app_id_start > 41) {
        entry->name[41] = ctx->app_id_start[41];
    }
    if (ctx->app_id_end - ctx->app_id_start > 42) {
        entry->name[42] = ctx->app_id_start[42];
    }
    if (ctx->app_id_end - ctx->app_id_start > 43) {
        entry->name[43] = ctx->app_id_start[43];
    }
    if (ctx->app_id_end - ctx->app_id_start > 44) {
        entry->name[44] = ctx->app_id_start[44];
    }
    if (ctx->app_id_end - ctx->app_id_start > 45) {
        entry->name[45] = ctx->app_id_start[45];
    }
    if (ctx->app_id_end - ctx->app_id_start > 46) {
        entry->name[46] = ctx->app_id_start[46];
    }
    if (ctx->app_id_end - ctx->app_id_start > 47) {
        entry->name[47] = ctx->app_id_start[47];
    }
    if (ctx->app_id_end - ctx->app_id_start > 48) {
        entry->name[48] = ctx->app_id_start[48];
    }
    if (ctx->app_id_end - ctx->app_id_start > 49) {
        entry->name[49] = ctx->app_id_start[49];
    }
    if (ctx->app_id_end - ctx->app_id_start > 50) {
        entry->name[50] = ctx->app_id_start[50];
    }
    if (ctx->app_id_end - ctx->app_id_start > 51) {
        entry->name[51] = ctx->app_id_start[51];
    }
    if (ctx->app_id_end - ctx->app_id_start > 52) {
        entry->name[52] = ctx->app_id_start[52];
    }
    if (ctx->app_id_end - ctx->app_id_start > 53) {
        entry->name[53] = ctx->app_id_start[53];
    }
    if (ctx->app_id_end - ctx->app_id_start > 54) {
        entry->name[54] = ctx->app_id_start[54];
    }
    if (ctx->app_id_end - ctx->app_id_start > 55) {
        entry->name[55] = ctx->app_id_start[55];
    }
    if (ctx->app_id_end - ctx->app_id_start > 56) {
        entry->name[56] = ctx->app_id_start[56];
    }
    if (ctx->app_id_end - ctx->app_id_start > 57) {
        entry->name[57] = ctx->app_id_start[57];
    }
    if (ctx->app_id_end - ctx->app_id_start > 58) {
        entry->name[58] = ctx->app_id_start[58];
    }
    if (ctx->app_id_end - ctx->app_id_start > 59) {
        entry->name[59] = ctx->app_id_start[59];
    }
    if (ctx->app_id_end - ctx->app_id_start > 60) {
        entry->name[60] = ctx->app_id_start[60];
    }
    if (ctx->app_id_end - ctx->app_id_start > 61) {
        entry->name[61] = ctx->app_id_start[61];
    }
    if (ctx->app_id_end - ctx->app_id_start > 62) {
        entry->name[62] = ctx->app_id_start[62];
    }
    if (ctx->app_id_end - ctx->app_id_start > 63) {
        entry->name[63] = ctx->app_id_start[63];
    }
#endif
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
