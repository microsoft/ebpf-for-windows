// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "libbpf.h"
#pragma warning(pop)
#include "libbpf_internal.h"

int
bpf_link__pin(struct bpf_link* link, const char* path)
{
    int err;

    if (link->pin_path)
        return -EBUSY;

    link->pin_path = strdup(path);
    if (!link->pin_path)
        return -ENOMEM;

    if (ebpf_object_pin(link->link_fd, link->pin_path)) {
        err = -errno;
        free(link->pin_path);
        link->pin_path = nullptr;
        return err;
    }

    return 0;
}

int
bpf_link__unpin(struct bpf_link* link)
{
    ebpf_result_t result;

    if (!link->pin_path)
        return -EINVAL;

    result = ebpf_object_unpin(link->pin_path);
    if (result != EBPF_SUCCESS) {
        return libbpf_err(result);
    }

    free(link->pin_path);
    link->pin_path = nullptr;
    return 0;
}