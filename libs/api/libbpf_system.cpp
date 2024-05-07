// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "libbpf.h"

#include <windows.h>

long
libbpf_get_error(const void* ptr)
{
    /* Older versions of Linux encode error numbers in a
     * void* in some cases, so libbpf has to deal with both
     * that case and the simple case of using errno, so
     * exposes this API to be agnostic.  But we always use
     * errno, so don't need to look at the ptr value.
     */
    UNREFERENCED_PARAMETER(ptr);

    return -errno;
}

int
libbpf_num_possible_cpus(void)
{
    return GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS);
}
