// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

static int
_bpf_link__pin(struct bpf_link* link, const char* path) noexcept
{
    ebpf_result_t result;

    if (link->pin_path)
        return libbpf_err(-EBUSY);

    link->pin_path = strdup(path);
    if (!link->pin_path)
        return libbpf_err(-ENOMEM);

    result = ebpf_object_pin(link->fd, link->pin_path);
    if (result != EBPF_SUCCESS) {
        free(link->pin_path);
        link->pin_path = nullptr;
    }

    return libbpf_result_err(result);
}

int
bpf_link__pin(struct bpf_link* link, const char* path)
{
    return _bpf_link__pin(link, path);
}

static int
_bpf_link__unpin(struct bpf_link* link) noexcept
{
    ebpf_result_t result;

    if (!link->pin_path)
        return libbpf_err(-ENOENT);

    result = ebpf_object_unpin(link->pin_path);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }

    free(link->pin_path);
    link->pin_path = nullptr;
    return 0;
}

int
bpf_link__unpin(struct bpf_link* link)
{
    return _bpf_link__unpin(link);
}

static void
_bpf_link__disconnect(struct bpf_link* link) noexcept
{
    link->disconnected = true;
}

void
bpf_link__disconnect(struct bpf_link* link)
{
    _bpf_link__disconnect(link);
}

static int
_bpf_link__destroy(struct bpf_link* link) noexcept
{
    if (link == nullptr) {
        return 0;
    }

    ebpf_result_t result = EBPF_SUCCESS;
    if (!link->disconnected) {
        result = ebpf_link_detach(link);
    }
    ebpf_link_close(link);

    return libbpf_result_err(result);
}

int
bpf_link__destroy(struct bpf_link* link)
{
    return _bpf_link__destroy(link);
}

static int
_bpf_link__fd(const struct bpf_link* link) noexcept
{
    return link->fd;
}

int
bpf_link__fd(const struct bpf_link* link)
{
    return _bpf_link__fd(link);
}

static int
_bpf_link_detach(int link_fd) noexcept
{
    return libbpf_result_err(ebpf_detach_link_by_fd(link_fd));
}

int
bpf_link_detach(int link_fd)
{
    return _bpf_link_detach(link_fd);
}

static int
_bpf_link_get_fd_by_id(uint32_t id) noexcept
{
    fd_t fd;
    ebpf_result_t result = ebpf_get_link_fd_by_id(id, &fd);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }
    return fd;
}

int
bpf_link_get_fd_by_id(uint32_t id)
{
    return _bpf_link_get_fd_by_id(id);
}

static int
_bpf_link_get_next_id(uint32_t start_id, uint32_t* next_id) noexcept
{
    return libbpf_result_err(ebpf_get_next_link_id(start_id, next_id));
}

int
bpf_link_get_next_id(uint32_t start_id, uint32_t* next_id)
{
    return _bpf_link_get_next_id(start_id, next_id);
}

static const char*
_libbpf_bpf_link_type_str(enum bpf_link_type t) noexcept
{
    if (t < 0 || t >= _countof(_ebpf_link_display_names))
        return nullptr;

    return _ebpf_link_display_names[t];
}

const char*
libbpf_bpf_link_type_str(enum bpf_link_type t)
{
    return _libbpf_bpf_link_type_str(t);
}