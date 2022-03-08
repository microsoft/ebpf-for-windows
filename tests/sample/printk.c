// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"

SEC("bind")
int
func()
{
    int bytes_written = 0;
    bytes_written += bpf_printk("Hello, world");
    bytes_written += bpf_printk("Hello, world\n");
    return bytes_written;
}
