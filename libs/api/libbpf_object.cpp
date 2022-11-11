// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

// This file implements APIs in LibBPF's libbpf.h and is based on code in external/libbpf/src/libbpf.c
// used under the BSD-2-Clause license, so the coding style tries to match the libbpf.c style to
// minimize diffs until libbpf becomes cross-platform capable.  This is a temporary workaround for
// issue #351 until we can compile and use libbpf.c directly.

static const char*
_bpf_object__name(const struct bpf_object* object) noexcept
{
    return object->object_name;
}

const char*
bpf_object__name(const struct bpf_object* object)
{
    return _bpf_object__name(object);
}

static int
_bpf_object__pin(struct bpf_object* obj, const char* path) noexcept
{
    int err;

    err = bpf_object__pin_maps(obj, path);
    if (err)
        return libbpf_err(err);

    err = bpf_object__pin_programs(obj, path);
    if (err) {
        bpf_object__unpin_maps(obj, path);
        return libbpf_err(err);
    }

    return 0;
}

int
bpf_object__pin(struct bpf_object* obj, const char* path)
{
    return _bpf_object__pin(obj, path);
}

static void
_bpf_object__close(struct bpf_object* object) noexcept
{
    ebpf_object_close(object);
}

void
bpf_object__close(struct bpf_object* object)
{
    _bpf_object__close(object);
}

static struct bpf_program*
_bpf_object__find_program_by_name(const struct bpf_object* obj, const char* name) noexcept
{
    struct bpf_program* prog;

    bpf_object__for_each_program(prog, obj)
    {
        if (!strcmp(prog->program_name, name))
            return prog;
    }
    return (struct bpf_program*)libbpf_err_ptr(-ENOENT);
}

struct bpf_program*
bpf_object__find_program_by_name(const struct bpf_object* obj, const char* name)
{
    return _bpf_object__find_program_by_name(obj, name);
}

static struct bpf_object*
_bpf_object__next(struct bpf_object* prev) noexcept
{
    return ebpf_object_next(prev);
}

struct bpf_object*
bpf_object__next(struct bpf_object* prev)
{
    return _bpf_object__next(prev);
}

// APIs from libbpf's bpf.h.

static int
_bpf_obj_get_info_by_fd(int bpf_fd, void* info, __u32* info_len) noexcept
{
    return libbpf_result_err(ebpf_object_get_info_by_fd((fd_t)bpf_fd, info, info_len));
}

int
bpf_obj_get_info_by_fd(int bpf_fd, void* info, __u32* info_len)
{
    return _bpf_obj_get_info_by_fd(bpf_fd, info, info_len);
}

static int
_bpf_obj_pin(int fd, const char* pathname) noexcept
{
    if (!pathname) {
        return libbpf_result_err(EBPF_INVALID_ARGUMENT);
    }
    return libbpf_result_err(ebpf_object_pin((fd_t)fd, pathname));
}

int
bpf_obj_pin(int fd, const char* pathname)
{
    return _bpf_obj_pin(fd, pathname);
}

static int
_bpf_obj_get(const char* pathname) noexcept
{
    return (int)ebpf_object_get(pathname);
}

int
bpf_obj_get(const char* pathname)
{
    return _bpf_obj_get(pathname);
}

static struct bpf_object*
_bpf_object__open(const char* path) noexcept
{
    return bpf_object__open_file(path, nullptr);
}

struct bpf_object*
bpf_object__open(const char* path)
{
    return _bpf_object__open(path);
}

static struct bpf_object*
_bpf_object__open_file(const char* path, const struct bpf_object_open_opts* opts) noexcept
{
    if (!path) {
        return (struct bpf_object*)libbpf_err_ptr(-EINVAL);
    }

    struct bpf_object* object = nullptr;
    const char* error_message;
    ebpf_result_t result = ebpf_object_open(
        path,
        ((opts) ? opts->object_name : nullptr),
        ((opts) ? opts->pin_root_path : nullptr),
        nullptr,
        nullptr,
        &object,
        &error_message);
    ebpf_free_string(error_message);
    libbpf_result_err(result); // Set errno.
    return object;
}

struct bpf_object*
bpf_object__open_file(const char* path, const struct bpf_object_open_opts* opts)
{
    return _bpf_object__open_file(path, opts);
}

static int
_bpf_object__load_xattr(struct bpf_object_load_attr* attr) noexcept
{
    ebpf_result_t result = ebpf_object_load(attr->obj);
    return libbpf_result_err(result);
}

int
bpf_object__load_xattr(struct bpf_object_load_attr* attr)
{
    return _bpf_object__load_xattr(attr);
}

static int
_bpf_object__load(struct bpf_object* object) noexcept
{
    ebpf_result_t result = ebpf_object_load(object);
    return libbpf_result_err(result);
}

int
bpf_object__load(struct bpf_object* object)
{
    return _bpf_object__load(object);
}

static int
_bpf_object__unload(struct bpf_object* obj) noexcept
{
    return libbpf_result_err(ebpf_object_unload(obj));
}

int
bpf_object__unload(struct bpf_object* obj)
{
    return _bpf_object__unload(obj);
}
