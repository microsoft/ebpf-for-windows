// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

SEC("sample_ext")
int
func(sample_program_context_t* ctx)
{
    int bytes_written = 0;

    bytes_written += bpf_printk("Hello, world");
    bytes_written += bpf_printk("Hello, world\n");

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    bytes_written += bpf_printk("PID: %u using %%u", pid_tgid >> 32);
    bytes_written += bpf_printk("PID: %lu using %%lu", pid_tgid >> 32);
    bytes_written += bpf_printk("PID: %llu using %%llu", pid_tgid >> 32);
    bytes_written += bpf_printk("DATA: %u VALUE: %u", ctx->uint32_data, ctx->uint16_data);
    bytes_written += bpf_printk(
        "DATA: %u VALUE: %u HELPER: %u", ctx->uint32_data, ctx->uint16_data, ctx->helper_data_1);

    bytes_written += bpf_printk("BAD1 %");
    bytes_written += bpf_printk("BAD2 %ll");
    bytes_written += bpf_printk("BAD3 %5d", ctx->uint32_data);
    bytes_written += bpf_printk("BAD4 %p", ctx->uint32_data);
    bytes_written += bpf_printk("BAD5", ctx->uint32_data);
    bytes_written += bpf_printk("BAD6 %u");
    bytes_written += bpf_printk("100%% done");

    return bytes_written;
}
