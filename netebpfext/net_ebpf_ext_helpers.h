// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file Prototypes and implementations for helper functions that are common to various programs types implemented in
 * netebpfext.
 */

#pragma once

#include <errno.h>
#include "ebpf_platform.h"

static inline int
_net_ebpf_ext_csum_diff(
    _In_reads_bytes_opt_(from_size) const void* from,
    int from_size,
    _In_reads_bytes_opt_(to_size) const void* to,
    int to_size,
    int seed)
{
    int csum_diff = -EINVAL;

    if ((from_size % 4 != 0) || (to_size % 4 != 0))
        // size of buffers should be a multiple of 4.
        goto Exit;

    csum_diff = seed;
    if (to != NULL)
        for (int i = 0; i < to_size / 2; i++)
            csum_diff += (uint16_t)(*((uint16_t*)to + i));
    if (from != NULL)
        for (int i = 0; i < from_size / 2; i++)
            csum_diff += (uint16_t)(~*((uint16_t*)from + i));

    // Adding 16-bit unsigned integers or their one's complement will produce a positive 32-bit integer,
    // unless the length of the buffers is so long, that the signed 32 bit output overflows and produces a negative
    // result.
    if (csum_diff < 0)
        csum_diff = -EINVAL;
Exit:
    return csum_diff;
}