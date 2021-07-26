// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "libbpf.h"
#pragma warning(pop)
#include "libbpf_internal.h"

// This file implements APIs in LibBPF's bpf.h
// and is based on code in libbpf.c.

static const ebpf_program_type_t*
_get_ebpf_program_type(enum bpf_prog_type type)
{
    // TODO(issue #223): read this mapping from the registry
    switch (type) {
    case BPF_PROG_TYPE_XDP:
        return &EBPF_PROGRAM_TYPE_XDP;
    }
    return nullptr;
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
    return BPF_ATTACH_TYPE_UNKNOWN;
}

int
bpf_prog_load(const char* file_name, enum bpf_prog_type type, struct bpf_object** object, int* program_fd)
{
    const ebpf_program_type_t* program_type = _get_ebpf_program_type(type);

    if (program_type == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    const char* log_buffer;
    return (int)ebpf_program_load(
        file_name, program_type, nullptr, EBPF_EXECUTION_ANY, object, (fd_t*)program_fd, &log_buffer);
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

struct bpf_link*
bpf_program__attach(struct bpf_program* program)
{
    if (program == nullptr) {
        return nullptr;
    }

    ebpf_handle_t link_handle;
    uint32_t result = ebpf_api_link_program(program->handle, program->attach_type, &link_handle);
    if (result) {
        errno = result;
        return nullptr;
    }

    // The bpf_link structure is opaque so we can use the link handle directly.
    return (struct bpf_link*)link_handle;
}

struct bpf_link*
bpf_program__attach_xdp(struct bpf_program* program, int ifindex)
{
    if (program == nullptr) {
        return nullptr;
    }

    // TODO: use ifindex
    UNREFERENCED_PARAMETER(ifindex);

    ebpf_handle_t link_handle;
    uint32_t result = ebpf_api_link_program(program->handle, EBPF_ATTACH_TYPE_XDP, &link_handle);
    if (result) {
        return nullptr;
    }

    // The bpf_link structure is opaque so we can use the link handle directly.
    return (struct bpf_link*)link_handle;
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
bpf_program__unpin(struct bpf_program* program, const char* path)
{
    char fullpath[MAX_PATH];
    int length = snprintf(fullpath, sizeof(fullpath), "%s/%s", path, program->program_name);
    if (length < 0) {
        return -EINVAL;
    } else if (length > sizeof(fullpath)) {
        return -ENAMETOOLONG;
    }

    uint32_t result = ebpf_api_unpin_object((const uint8_t*)fullpath, (uint32_t)strlen(fullpath));
    return (int)result;
}

static void
_unpin_previous_programs(_In_ ebpf_program_t* program, _In_ struct bpf_object* object, const char* path)
{
    for (program = bpf_program__prev(program, object); program; program = bpf_program__prev(program, object)) {
        bpf_program__unpin(program, path);
    }
}

int
bpf_program__pin(struct bpf_program* program, const char* path)
{
    char fullpath[MAX_PATH];
    int result;

    int length = snprintf(fullpath, sizeof(fullpath), "%s/%s", path, program->program_name);
    if (length < 0) {
        return libbpf_err(-EINVAL);
    }

    result = ebpf_api_pin_object(program->handle, (const uint8_t*)fullpath, (uint32_t)strlen(fullpath));
    if (result) {
        return libbpf_err(result);
    }

    return 0;
}

int
bpf_object__pin_programs(struct bpf_object* object, const char* path)
{
    struct bpf_program* program;

    if (!object) {
        return libbpf_err(-ENOENT);
    }

    bpf_object__for_each_program(program, object)
    {
        int result = bpf_program__pin(program, path);
        if (result) {
            _unpin_previous_programs(program, object, path);
            return result;
            ;
        }
    }

    return 0;
}

int
bpf_object__unpin_programs(struct bpf_object* object, const char* path)
{
    struct bpf_program* program;

    if (!object) {
        return libbpf_err(-ENOENT);
    }

    bpf_object__for_each_program(program, object)
    {
        int result = bpf_program__unpin(program, path);
        if (result) {
            return libbpf_err(result);
        }
    }

    return 0;
}

int
bpf_link__destroy(struct bpf_link* link)
{
    ebpf_handle_t link_handle = (ebpf_handle_t)link;
    uint32_t result = ebpf_api_close_handle(link_handle);
    return (int)result;
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
