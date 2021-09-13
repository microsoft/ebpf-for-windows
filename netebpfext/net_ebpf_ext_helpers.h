// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file Prototypes and implementations for helper functions that are common to various programs types implemented in
 * netebpfext.
 */

#pragma once
#include "ebpf_platform.h"

// static uint16_t
// _ntohs(uint16_t us)
// {
//     return us << 8 | us >> 8;
// }

static int
_partial_sum(_In_ const void* buffer, int buffer_len)
{
    int partial_sum = 0;
    for (int i = 0; i < buffer_len / 2; i++)
        partial_sum += *((uint16_t*)buffer + i);
    return partial_sum;
}

static int
_net_ebpf_ext_csum_diff(_In_opt_ const void* from, int from_size, _In_opt_ const void* to, int to_size, int seed)
{
    int csum_diff = -1;

    if ((from_size % 4 != 0) || (to_size % 4 != 0))
        // size of buffers should be multiples of 4.
        goto Exit;

    if ((from == NULL) && (to == NULL)) {
        // Trivial case.
        csum_diff = 0;
        goto Exit;
    }

    if ((from != NULL && to != NULL) && (from_size == to_size) && RtlCompareMemory(from, to, from_size) == 0) {
        // Buffers are same.
        csum_diff = 0;
        goto Exit;
    }

    csum_diff = seed;
    if ((to != NULL) && (to_size > 0))
        csum_diff += _partial_sum(to, to_size);
    if ((from != NULL) && (from_size > 0))
        csum_diff -= _partial_sum(from, from_size);
Exit:
    return csum_diff;
}
