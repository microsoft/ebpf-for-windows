// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

__attribute__((noinline)) int
btf_lookup(uint32_t key)
{
    uint64_t value = 0;
    return sample_ebpf_extension_btf_lookup(key, &value, sizeof(value));
}

SEC("sample_ext")
int
func(sample_program_context_t* ctx)
{
    return btf_lookup(ctx->uint32_data);
}
