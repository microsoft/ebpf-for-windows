// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

SEC("bind")
int
func(bind_md_t* ctx)
{
    uint64_t value = 0;
    return sample_ebpf_extension_btf_lookup(ctx->process_id, &value, sizeof(value));
}
