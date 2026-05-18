// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Sample program to validate native parsing when multiple top-level programs
// share the same short section name (<= 8 chars).

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

SEC("bind")
bind_action_t
ShortBindEntryOne(bind_md_t* ctx)
{
    (void)ctx;
    return BIND_PERMIT_SOFT;
}

SEC("bind")
bind_action_t
ShortBindEntryTwo(bind_md_t* ctx)
{
    (void)ctx;
    return BIND_REDIRECT;
}
