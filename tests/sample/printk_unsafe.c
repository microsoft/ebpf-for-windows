// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"

SEC("bind")
int
func(bind_md_t* ctx)
{
    // One should not be able to pass a pointer to be displayed,
    // so this program should fail verification.
    bpf_printk("ctx: %u", (uint64_t)ctx);
    return 0;
}
