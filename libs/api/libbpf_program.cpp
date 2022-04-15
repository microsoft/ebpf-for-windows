// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"
#include "platform.h"

// This file implements APIs in LibBPF's libbpf.h and is based on code in external/libbpf/src/libbpf.c
// used under the BSD-2-Clause license, so the coding style tries to match the libbpf.c style to
// minimize diffs until libbpf becomes cross-platform capable.  This is a temporary workaround for
// issue #351 until we can compile and use libbpf.c directly.

static const ebpf_program_type_t*
_get_ebpf_program_type(enum bpf_prog_type type)
{
    const ebpf_program_type_t* program_type = nullptr;
    // TODO(issue #223): read this mapping from the registry
    switch (type) {
    case BPF_PROG_TYPE_XDP:
        program_type = &EBPF_PROGRAM_TYPE_XDP;
        break;
    case BPF_PROG_TYPE_BIND:
        program_type = &EBPF_PROGRAM_TYPE_BIND;
        break;
    case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
        program_type = &EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
        break;
    case BPF_PROG_TYPE_SOCK_OPS:
        program_type = &EBPF_PROGRAM_TYPE_SOCK_OPS;
        break;
    }
    return program_type;
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
    const ebpf_attach_type_t* attach_type = nullptr;

    // TODO(issue #223): read this mapping from the registry
    switch (type) {
    case BPF_XDP:
        attach_type = &EBPF_ATTACH_TYPE_XDP;
        break;
    case BPF_CGROUP_INET4_CONNECT:
        attach_type = &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT;
        break;
    case BPF_CGROUP_INET6_CONNECT:
        attach_type = &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT;
        break;
    case BPF_CGROUP_INET4_RECV_ACCEPT:
        attach_type = &EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT;
        break;
    case BPF_CGROUP_INET6_RECV_ACCEPT:
        attach_type = &EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT;
        break;
    case BPF_CGROUP_SOCK_OPS:
        attach_type = &EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS;
        break;
    }

    return attach_type;
}

static enum bpf_attach_type
_get_bpf_attach_type(const ebpf_attach_type_t* type)
{
    // TODO(issue #223): read this mapping from the registry
    if (memcmp(type, &EBPF_ATTACH_TYPE_XDP, sizeof(*type)) == 0) {
        return BPF_XDP;
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
    load_attr.name = NULL;
    load_attr.insns = insns;
    load_attr.insns_cnt = insns_cnt;
    load_attr.license = license;
    load_attr.kern_version = kern_version;

    return bpf_load_program_xattr(&load_attr, log_buf, log_buf_sz);
}

int
bpf_prog_load_deprecated(const char* file_name, enum bpf_prog_type type, struct bpf_object** object, int* program_fd)
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
bpf_program__name(const struct bpf_program* prog)
{
    return prog->program_name;
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
bpf_program__attach(const struct bpf_program* program)
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
bpf_program__attach_xdp(const struct bpf_program* program, int ifindex)
{
    if (program == nullptr) {
        errno = EINVAL;
        return nullptr;
    }

    bpf_link* link = nullptr;
    ebpf_result_t result = ebpf_program_attach(program, &EBPF_ATTACH_TYPE_XDP, &ifindex, sizeof(ifindex), &link);
    if (result) {
        errno = ebpf_result_to_errno(result);
    }

    return link;
}

static bool
_does_attach_type_support_attachable_fd(enum bpf_attach_type type)
{
    bool supported = FALSE;

    switch (type) {
    case BPF_CGROUP_INET4_CONNECT:
    case BPF_CGROUP_INET6_CONNECT:
    case BPF_CGROUP_INET4_RECV_ACCEPT:
    case BPF_CGROUP_INET6_RECV_ACCEPT:
    case BPF_CGROUP_SOCK_OPS:
        supported = TRUE;
        break;
    }

    return supported;
}

int
bpf_prog_attach(int prog_fd, int attachable_fd, enum bpf_attach_type type, unsigned int flags)
{
    bpf_link* link = nullptr;
    ebpf_result_t result = EBPF_SUCCESS;

    UNREFERENCED_PARAMETER(flags);

    if (_does_attach_type_support_attachable_fd(type)) {
        result = ebpf_program_attach_by_fd(
            prog_fd, _get_ebpf_attach_type(type), &attachable_fd, sizeof(attachable_fd), &link);
    } else {
        result = EBPF_OPERATION_NOT_SUPPORTED;
    }

    if (result != EBPF_SUCCESS)
        errno = ebpf_result_to_errno(result);

    return (result == EBPF_SUCCESS) ? 0 : -1;
}

struct bpf_program*
bpf_program__next(struct bpf_program* prev, const struct bpf_object* obj)
{
    return bpf_object__next_program(obj, prev);
}

struct bpf_program*
bpf_object__next_program(const struct bpf_object* obj, struct bpf_program* prev)
{
    return ebpf_program_next(prev, obj);
}

struct bpf_program*
bpf_program__prev(struct bpf_program* next, const struct bpf_object* obj)
{
    return bpf_object__prev_program(obj, next);
}

struct bpf_program*
bpf_object__prev_program(const struct bpf_object* obj, struct bpf_program* next)
{
    return ebpf_program_previous(next, obj);
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
        *expected_attach_type = BPF_XDP;
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

static int
__bpf_set_link_xdp_fd_replace(int ifindex, int fd, int old_fd, __u32 flags)
{
    ebpf_result_t result = EBPF_SUCCESS;

    // On Linux, the logic to detach the older program and attach the
    // new program is present in kernel (the flag XDP_FLAGS_REPLACE is
    // passed to the kernel).  Thus, we should consider moving this
    // logic to the execution context.
    if (flags & XDP_FLAGS_REPLACE) {
        // Look up the old program info to get the program ID.
        ebpf_id_t program_id = 0;
        if (old_fd == 0 || old_fd == ebpf_fd_invalid) {
            int err = bpf_xdp_query_id(ifindex, 0, &program_id);
            if ((err < 0) && (errno != ENOENT)) {
                return err;
            }
            // We found the right program_id.
        } else {
            struct bpf_prog_info prog_info;
            uint32_t info_len = sizeof(prog_info);
            int err = bpf_obj_get_info_by_fd(old_fd, &prog_info, &info_len);
            if (err < 0) {
                return err;
            }

            // Verify that the program is actually an XDP program.
            if (prog_info.type != BPF_PROG_TYPE_XDP) {
                return libbpf_err(-EINVAL);
            }

            program_id = prog_info.id;
        }

        if (program_id != 0) {
            // Unlink the old program from the specified ifindex.
            uint32_t link_id = 0;
            while (bpf_link_get_next_id(link_id, &link_id) == 0) {
                fd_t link_fd = bpf_link_get_fd_by_id(link_id);
                if (link_fd < 0) {
                    continue;
                }

                struct bpf_link_info link_info;
                uint32_t info_len = sizeof(link_info);
                if (bpf_obj_get_info_by_fd(link_fd, &link_info, &info_len) == 0) {
                    if (link_info.prog_id == program_id && link_info.xdp.ifindex == (uint32_t)ifindex) {
                        if (bpf_link_detach(link_fd) < 0) {
                            return libbpf_err(-errno);
                        }
                    }
                }

                Platform::_close(link_fd);
            }
        }
    }

    if (fd != ebpf_fd_invalid) {
        // Link the new program fd to the specified ifindex.
        struct bpf_link* link;
        result = ebpf_program_attach_by_fd(fd, &EBPF_ATTACH_TYPE_XDP, &ifindex, sizeof(ifindex), &link);
    }
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }
    return 0;
}

int
bpf_xdp_attach(int ifindex, int prog_fd, __u32 flags, const struct bpf_xdp_attach_opts* opts)
{
    int old_prog_fd, err;

    old_prog_fd = (opts) ? opts->old_prog_fd : ebpf_fd_invalid;

    err = __bpf_set_link_xdp_fd_replace(ifindex, prog_fd, old_prog_fd, flags);
    return libbpf_err(err);
}

int
bpf_xdp_detach(int ifindex, __u32 flags, const struct bpf_xdp_attach_opts* opts)
{
    return bpf_xdp_attach(ifindex, -1, flags, opts);
}

int
bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags)
{
    int ret;

    ret = __bpf_set_link_xdp_fd_replace(ifindex, fd, 0, flags);
    return libbpf_err(ret);
}

int
bpf_xdp_query_id(int ifindex, int flags, __u32* prog_id)
{
    UNREFERENCED_PARAMETER(flags);

    *prog_id = 0;
    for (uint32_t link_id = 0;;) {
        int err = bpf_link_get_next_id(link_id, &link_id);
        if (err < 0) {
            return err;
        }
        fd_t link_fd = bpf_link_get_fd_by_id(link_id);
        if (link_fd == ebpf_fd_invalid) {
            return libbpf_err(-ENOENT);
        }

        struct bpf_link_info link_info;
        uint32_t info_size = sizeof(link_info);
        err = bpf_obj_get_info_by_fd(link_fd, &link_info, &info_size);
        Platform::_close(link_fd);
        if (err != 0) {
            return err;
        }

        if ((memcmp(&link_info.program_type_uuid, &EBPF_PROGRAM_TYPE_XDP, sizeof(link_info.program_type_uuid)) == 0) &&
            (link_info.xdp.ifindex == (uint32_t)ifindex) && (link_info.prog_id != EBPF_ID_NONE)) {
            *prog_id = link_info.prog_id;
            return 0;
        }
    }
}
