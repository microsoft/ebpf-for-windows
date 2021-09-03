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
    ebpf_result_t result;

    if (link->pin_path)
        return libbpf_err(-EBUSY);

    link->pin_path = strdup(path);
    if (!link->pin_path)
        return libbpf_err(-ENOMEM);

    result = ebpf_object_pin(link->link_fd, link->pin_path);
    if (result != EBPF_SUCCESS) {
        free(link->pin_path);
        link->pin_path = nullptr;
    }

    return libbpf_err(-result);
}

int
bpf_link__unpin(struct bpf_link* link)
{
    ebpf_result_t result;

    if (!link->pin_path)
        return libbpf_err(-EINVAL);

    result = ebpf_object_unpin(link->pin_path);
    if (result != EBPF_SUCCESS) {
        return libbpf_err(-result);
    }

    free(link->pin_path);
    link->pin_path = nullptr;
    return 0;
}

void
bpf_link__disconnect(struct bpf_link* link)
{
    link->disconnected = true;
}

int
bpf_link__destroy(struct bpf_link* link)
{
    if (link == nullptr) {
        return 0;
    }

    ebpf_result_t result = EBPF_SUCCESS;
    if (!link->disconnected) {
        result = ebpf_link_detach(link);
    }
    ebpf_link_close(link);

    return libbpf_err(-(int)result);
}
