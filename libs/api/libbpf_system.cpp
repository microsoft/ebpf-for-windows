// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <windows.h>
#pragma warning(push)
#pragma warning(disable : 4200)
#include "libbpf.h"
#pragma warning(pop)

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
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwNumberOfProcessors;
}
