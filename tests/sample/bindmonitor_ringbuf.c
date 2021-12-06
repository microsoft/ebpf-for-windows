// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

#pragma clang section data = "maps"
ebpf_map_definition_in_file_t process_map = {
    .size = sizeof(ebpf_map_definition_in_file_t), .type = BPF_MAP_TYPE_RINGBUF, .max_entries = 256 * 1024};

#pragma clang section text = "bind"
bind_action_t
bind_monitor(bind_md_t* ctx)
{
    switch (ctx->operation) {
    case BIND_OPERATION_BIND:
        if (ctx->app_id_end > ctx->app_id_start)
            (void)bpf_ringbuf_output(&process_map, ctx->app_id_start, ctx->app_id_end - ctx->app_id_start, 0);
        break;
    default:
        break;
    }

    return BIND_PERMIT;
}
