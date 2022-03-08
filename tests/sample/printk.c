// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

SEC("bind")
int
func(bind_md_t* ctx)
{
    int bytes_written = 0;

    // The following two lines should have identical output.
    bytes_written += bpf_printk("Hello, world");
    bytes_written += bpf_printk("Hello, world\n");

    // Now try additional arguments.
    bytes_written += bpf_printk("PID: %u", ctx->process_id);
    bytes_written += bpf_printk("PID: %u PROTO: %u", ctx->process_id, ctx->protocol);
    bytes_written +=
        bpf_printk("PID: %u PROTO: %u ADDRLEN: %u", ctx->process_id, ctx->protocol, ctx->socket_address_length);

    return bytes_written;
}
