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

const char*
bpf_object__name(const struct bpf_object* object)
{
    return object->file_name;
}

int
bpf_object__pin(struct bpf_object* obj, const char* path)
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

void
bpf_object__close(struct bpf_object* object)
{
    ebpf_object_close(object);
}

struct bpf_program*
bpf_object__find_program_by_name(const struct bpf_object* object, const char* name)
{
    struct bpf_program* program;

    bpf_object__for_each_program(program, object)
    {
        if (!strcmp(program->program_name, name))
            return program;
    }
    errno = ENOENT;
    return nullptr;
}
