// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#define PATH_MAX MAX_PATH

static inline int
libbpf_err(int ret)
{
    if (ret < 0)
        errno = -ret;
    return ret;
}
