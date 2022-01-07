// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "libbpf.h"
#pragma warning(pop)
#include "libbpf_internal.h"

// This file implements APIs in LibBPF's libbpf.h and is based on code in external/libbpf/src/libbpf.c
// used under the BSD-2-Clause license , so the coding style tries to match the libbpf.c style to
// minimize diffs until libbpf becomes cross-platform capable.  This is a temporary workaround for
// issue #351 until we can compile and use libbpf.c directly.

static const ebpf_program_type_t*
_get_ebpf_program_type(enum bpf_prog_type type)
{
    // TODO(issue #223): read this mapping from the registry
    switch (type) {
    case BPF_PROG_TYPE_XDP:
        return &EBPF_PROGRAM_TYPE_XDP;
    case BPF_PROG_TYPE_BIND:
        return &EBPF_PROGRAM_TYPE_BIND;
    }
    return nullptr;
}

static enum bpf_prog_type
_get_bpf_program_type(const ebpf_program_type_t* type)
{
    // TODO(issue #223): read this mapping from the registry
    if (memcmp(type, &EBPF_PROGRAM_TYPE_XDP, sizeof(*type)) == 0) {
        return BPF_PROG_TYPE_XDP;
    }
    if (memcmp(type, &EBPF_PROGRAM_TYPE_BIND, sizeof(*type)) == 0) {
        return BPF_PROG_TYPE_BIND;
    }
    return BPF_PROG_TYPE_UNSPEC;
}

static const ebpf_attach_type_t*
_get_ebpf_attach_type(enum bpf_attach_type type)
{
    // TODO(issue #223): read this mapping from the registry
    switch (type) {
    case BPF_ATTACH_TYPE_XDP:
        return &EBPF_ATTACH_TYPE_XDP;
    }
    return nullptr;
}

static enum bpf_attach_type
_get_bpf_attach_type(const ebpf_attach_type_t* type)
{
    // TODO(issue #223): read this mapping from the registry
    if (memcmp(type, &EBPF_ATTACH_TYPE_XDP, sizeof(*type)) == 0) {
        return BPF_ATTACH_TYPE_XDP;
    }
    return BPF_ATTACH_TYPE_UNSPEC;
}

int
bpf_load_program_xattr(const struct bpf_load_program_attr* load_attr, char* log_buf, size_t log_buf_sz)
{
    size_t byte_code_size = load_attr->insns_cnt * sizeof(struct ebpf_inst);
    if (byte_code_size < 1 || byte_code_size > UINT32_MAX) {
        return libbpf_err(-EINVAL);
    }

    const ebpf_program_type_t* program_type = _get_ebpf_program_type(load_attr->prog_type);
    if (program_type == nullptr) {
        return libbpf_err(-EINVAL);
    }

    fd_t program_fd;
    ebpf_result_t result = ebpf_program_load_bytes(
        program_type,
        EBPF_EXECUTION_ANY,
        (const uint8_t*)load_attr->insns,
        (uint32_t)byte_code_size,
        log_buf,
        log_buf_sz,
        &program_fd);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }
    return program_fd;
}

int
bpf_load_program(
    enum bpf_prog_type type,
    const struct bpf_insn* insns,
    size_t insns_cnt,
    const char* license,
    __u32 kern_version,
    char* log_buf,
    size_t log_buf_sz)
{
    struct bpf_load_program_attr load_attr;

    memset(&load_attr, 0, sizeof(struct bpf_load_program_attr));
    load_attr.prog_type = type;
    load_attr.expected_attach_type = BPF_ATTACH_TYPE_UNSPEC;
    load_attr.name = nullptr;
    load_attr.insns = insns;
    load_attr.insns_cnt = insns_cnt;
    load_attr.license = license;
    load_attr.kern_version = kern_version;

    return bpf_load_program_xattr(&load_attr, log_buf, log_buf_sz);
}

int
bpf_prog_load(const char* file_name, enum bpf_prog_type type, struct bpf_object** object, int* program_fd)
{
    const ebpf_program_type_t* program_type = _get_ebpf_program_type(type);

    if (program_type == nullptr) {
        return libbpf_err(-EINVAL);
    }

    const char* log_buffer;
    ebpf_result_t result =
        ebpf_program_load(file_name, program_type, nullptr, EBPF_EXECUTION_ANY, object, (fd_t*)program_fd, &log_buffer);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }
    return 0;
}

int
bpf_program__fd(const struct bpf_program* program)
{
    return (int)ebpf_program_get_fd(program);
}

const char*
bpf_program__name(const struct bpf_program* program)
{
    return program->program_name;
}

const char*
bpf_program__section_name(const struct bpf_program* program)
{
    return program->section_name;
}

size_t
bpf_program__size(const struct bpf_program* program)
{
    return program->byte_code_size;
}

struct bpf_link*
bpf_program__attach(struct bpf_program* program)
{
    if (program == nullptr) {
        errno = EINVAL;
        return nullptr;
    }

    bpf_link* link = nullptr;
    ebpf_result_t result = ebpf_program_attach(program, nullptr, nullptr, 0, &link);
    if (result) {
        errno = ebpf_result_to_errno(result);
    }

    return link;
}

struct bpf_link*
bpf_program__attach_xdp(struct bpf_program* program, int ifindex)
{
    if (program == nullptr) {
        errno = EINVAL;
        return nullptr;
    }

    // TODO: use ifindex
    UNREFERENCED_PARAMETER(ifindex);

    bpf_link* link = nullptr;
    ebpf_result_t result = ebpf_program_attach(program, &EBPF_ATTACH_TYPE_XDP, nullptr, 0, &link);
    if (result) {
        errno = ebpf_result_to_errno(result);
    }

    return link;
}

struct bpf_program*
bpf_program__next(struct bpf_program* previous, const struct bpf_object* object)
{
    return ebpf_program_next(previous, object);
}

struct bpf_program*
bpf_program__prev(struct bpf_program* next, const struct bpf_object* object)
{
    return ebpf_program_previous(next, object);
}

int
bpf_program__unpin(struct bpf_program* prog, const char* path)
{
    ebpf_result_t result;

    if (prog == NULL) {
        return libbpf_err(-EINVAL);
    }

    result = ebpf_object_unpin(path);
    if (result)
        return libbpf_result_err(result);

    return 0;
}

int
bpf_program__pin(struct bpf_program* prog, const char* path)
{
    ebpf_result_t result;

    if (prog == NULL) {
        return libbpf_err(-EINVAL);
    }

    result = ebpf_object_pin(prog->fd, path);
    if (result) {
        return libbpf_result_err(result);
    }

    return 0;
}

static char*
__bpf_program__pin_name(struct bpf_program* prog)
{
    char *name, *p;

    name = p = strdup(prog->section_name);
    while ((p = strchr(p, '/')) != NULL)
        *p = '_';

    return name;
}

int
bpf_object__pin_programs(struct bpf_object* obj, const char* path)
{
    struct bpf_program* prog;
    int err;

    if (!obj)
        return libbpf_err(-ENOENT);

    bpf_object__for_each_program(prog, obj)
    {
        char buf[PATH_MAX];
        int len;

        len = snprintf(buf, PATH_MAX, "%s/%s", path, __bpf_program__pin_name(prog));
        if (len < 0) {
            err = -EINVAL;
            goto err_unpin_programs;
        } else if (len >= PATH_MAX) {
            err = -ENAMETOOLONG;
            goto err_unpin_programs;
        }

        err = bpf_program__pin(prog, buf);
        if (err) {
            goto err_unpin_programs;
        }
    }

    return 0;

err_unpin_programs:
    while ((prog = bpf_program__prev(prog, obj)) != NULL) {
        char buf[PATH_MAX];
        int len;

        len = snprintf(buf, PATH_MAX, "%s/%s", path, __bpf_program__pin_name(prog));
        if (len < 0)
            continue;
        else if (len >= PATH_MAX)
            continue;

        bpf_program__unpin(prog, path);
    }
    return err;
}

int
bpf_object__unpin_programs(struct bpf_object* obj, const char* path)
{
    struct bpf_program* prog;
    int err;

    if (!obj)
        return libbpf_err(-ENOENT);

    bpf_object__for_each_program(prog, obj)
    {
        char buf[PATH_MAX];
        int len;

        len = snprintf(buf, PATH_MAX, "%s/%s", path, __bpf_program__pin_name(prog));
        if (len < 0)
            return libbpf_err(-EINVAL);
        else if (len >= PATH_MAX)
            return libbpf_err(-ENAMETOOLONG);

        err = bpf_program__unpin(prog, buf);
        if (err)
            return libbpf_err(err);
    }

    return 0;
}

enum bpf_attach_type
bpf_program__get_expected_attach_type(const struct bpf_program* program)
{
    return _get_bpf_attach_type(&program->attach_type);
}

void
bpf_program__set_expected_attach_type(struct bpf_program* program, enum bpf_attach_type type)
{
    program->attach_type = *_get_ebpf_attach_type(type);
}

enum bpf_prog_type
bpf_program__get_type(const struct bpf_program* program)
{
    return _get_bpf_program_type(&program->program_type);
}

void
bpf_program__set_type(struct bpf_program* program, enum bpf_prog_type type)
{
    const ebpf_program_type_t* program_type = _get_ebpf_program_type(type);
    program->program_type = (program_type != nullptr) ? *program_type : EBPF_PROGRAM_TYPE_UNSPECIFIED;
}

int
bpf_prog_get_fd_by_id(uint32_t id)
{
    fd_t fd;
    ebpf_result_t result = ebpf_get_program_fd_by_id(id, &fd);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }
    return fd;
}

int
bpf_prog_get_next_id(uint32_t start_id, uint32_t* next_id)
{
    return libbpf_result_err(ebpf_get_next_program_id(start_id, next_id));
}

int
libbpf_prog_type_by_name(const char* name, enum bpf_prog_type* prog_type, enum bpf_attach_type* expected_attach_type)
{
    if (prog_type == nullptr || expected_attach_type == nullptr) {
        return libbpf_err(-EINVAL);
    }

    ebpf_program_type_t program_type_uuid;
    ebpf_attach_type_t expected_attach_type_uuid;
    ebpf_result_t result = ebpf_get_program_type_by_name(name, &program_type_uuid, &expected_attach_type_uuid);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }

    // Convert UUIDs to enum values if they exist.
    // TODO(issue #223): get info from registry.
    if (memcmp(&program_type_uuid, &EBPF_PROGRAM_TYPE_XDP, sizeof(program_type_uuid)) == 0) {
        *prog_type = BPF_PROG_TYPE_XDP;
        *expected_attach_type = BPF_ATTACH_TYPE_XDP;
        return 0;
    }
    if (memcmp(&program_type_uuid, &EBPF_PROGRAM_TYPE_BIND, sizeof(program_type_uuid)) == 0) {
        *prog_type = BPF_PROG_TYPE_BIND;
        *expected_attach_type = BPF_ATTACH_TYPE_UNSPEC;
        return 0;
    }

    errno = ESRCH;
    return -1;
}

void
bpf_program__unload(struct bpf_program* prog)
{
    ebpf_result_t result = ebpf_program_unload(prog);
    if (result != EBPF_SUCCESS) {
        errno = ebpf_result_to_errno(result);
    }
}

int
bpf_prog_bind_map(int prog_fd, int map_fd, const struct bpf_prog_bind_opts* opts)
{
    UNREFERENCED_PARAMETER(opts);

    return libbpf_result_err(ebpf_program_bind_map(prog_fd, map_fd));
}
