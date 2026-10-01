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

SEC("sample_ext")
int
func(sample_program_context_t* ctx)
{
    int bytes_written = 0;

    // The following two lines should have identical output.
    bytes_written += bpf_printk("Hello, world");
    bytes_written += bpf_printk("Hello, world\n");

    // Now try additional arguments.
    // The caller supplies the PID via ctx->helper_data_2 (bpf_get_current_pid_tgid isn't wired up for native DLLs).
    uint32_t pid = ctx->helper_data_2;
    bytes_written += bpf_printk("PID: %u using %%u", pid);
    bytes_written += bpf_printk("PID: %lu using %%lu", pid);
    bytes_written += bpf_printk("PID: %llu using %%llu", pid);
    bytes_written += bpf_printk("DATA: %u VALUE: %u", ctx->uint32_data, ctx->uint16_data);
    bytes_written +=
        bpf_printk("DATA: %u VALUE: %u HELPER: %u", ctx->uint32_data, ctx->uint16_data, ctx->helper_data_1);

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
