// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

// Prior to Linux 5.3, it was common for eBPF programs to define bpf_printk themselves.
#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

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

    // Try some invalid format specifiers.
    // These should each return -1.
    bytes_written += bpf_printk("BAD1 %");
    bytes_written += bpf_printk("BAD2 %ll");
    bytes_written += bpf_printk("BAD3 %5d", ctx->process_id);
    bytes_written += bpf_printk("BAD4 %p", ctx->process_id);

    // Try some mismatched format specifiers.
    // These should also return -1.
    bytes_written += bpf_printk("BAD5", ctx->process_id);
    bytes_written += bpf_printk("BAD6 %u");

    // And try %%.
    bytes_written += bpf_printk("100%% done");

    return bytes_written;
}
