// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#define PATH_MAX MAX_PATH
#define strdup _strdup

static inline int
libbpf_err(int ret)
{
    if (ret < 0)
        errno = -ret;
    return ret;
}

static inline int
libbpf_result_err(ebpf_result_t result)
{
    return libbpf_err(-ebpf_result_to_errno(result));
}

static inline void*
libbpf_err_ptr(int err)
{
    errno = -err;
    return NULL;
}
