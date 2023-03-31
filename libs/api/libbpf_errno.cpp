// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

int
libbpf_strerror(int err, char* buf, size_t size)
{
    if (!buf || !size) {
        return libbpf_err(-EINVAL);
    }

    err = err > 0 ? err : -err;

    snprintf(buf, size, "Unknown libbpf error %d", err);
    buf[size - 1] = '\0';
    return libbpf_err(-ENOENT);
}
