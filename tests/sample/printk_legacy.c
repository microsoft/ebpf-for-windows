// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

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
#include "sample_ext_helpers.h"

// Prior to Linux 5.3, it was common for eBPF programs to define bpf_printk themselves.
#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

SEC("sample_ext")
int
func(sample_program_context_t* ctx)
{
    int bytes_written = 0;

    // The following two lines should have identical output.
    bytes_written += bpf_printk("Hello, world");
    bytes_written += bpf_printk("Hello, world\n");

    // Now try additional arguments.
    bytes_written += bpf_printk("PID: %u", ctx->helper_data_2);
    bytes_written += bpf_printk("PID: %u PROTO: %u", ctx->helper_data_2, ctx->uint16_data);
    bytes_written +=
        bpf_printk("PID: %u PROTO: %u ADDRLEN: %u", ctx->helper_data_2, ctx->uint16_data, ctx->uint32_data);

    // Try some invalid format specifiers.
    // These should each return -1.
    bytes_written += bpf_printk("BAD1 %");
    bytes_written += bpf_printk("BAD2 %ll");
    bytes_written += bpf_printk("BAD3 %5d", ctx->uint32_data);
    bytes_written += bpf_printk("BAD4 %p", ctx->uint32_data);

    // Try some mismatched format specifiers.
    // These should also return -1.
    bytes_written += bpf_printk("BAD5", ctx->uint32_data);
    bytes_written += bpf_printk("BAD6 %u");

    // And try %%.
    bytes_written += bpf_printk("100%% done");

    return bytes_written;
}
