// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "libbpf.h"
#pragma warning(pop)
#include "libbpf_internal.h"

// This file implements APIs in LibBPF's bpf.h
// and is based on code in libbpf.c, so the
// coding style tries to match the libbpf.c
// style to minimize diffs until libbpf becomes
// cross-platform capable.

struct bpf_map*
bpf_map__next(const struct bpf_map* previous, const struct bpf_object* object)
{
    return ebpf_map_next(previous, object);
}

struct bpf_map*
bpf_map__prev(const struct bpf_map* next, const struct bpf_object* object)
{
    return ebpf_map_previous(next, object);
}

int
bpf_map__unpin(struct bpf_map* map, const char* path)
{
    int err;

    if (map == NULL) {
        return libbpf_err(-EINVAL);
    }

    err = ebpf_api_unpin_object((const uint8_t*)path, (uint32_t)strlen(path));
    if (err) {
        return libbpf_err(err);
    }

    map->pinned = false;

    return 0;
}

int
bpf_map__pin(struct bpf_map* map, const char* path)
{
    int err;

    if (map == NULL) {
        return libbpf_err(-EINVAL);
    }

    err = ebpf_api_pin_object(map->map_handle, (const uint8_t*)path, (uint32_t)strlen(path));
    if (err)
        return libbpf_err(-err);

    map->pinned = true;

    return 0;
}

int
bpf_object__pin_maps(struct bpf_object* obj, const char* path)
{
    struct bpf_map* map;
    int err;

    if (!obj)
        return libbpf_err(-ENOENT);

    bpf_object__for_each_map(map, obj)
    {
        char* pin_path = NULL;
        char buf[PATH_MAX];

        if (path) {
            int len;

            len = snprintf(buf, PATH_MAX, "%s/%s", path, bpf_map__name(map));
            if (len < 0) {
                err = -EINVAL;
                goto err_unpin_maps;
            } else if (len >= PATH_MAX) {
                err = -ENAMETOOLONG;
                goto err_unpin_maps;
            }
            pin_path = buf;
        } else {
            continue;
        }

        err = bpf_map__pin(map, pin_path);
        if (err)
            goto err_unpin_maps;
    }

    return 0;

err_unpin_maps:
    while ((map = bpf_map__prev(map, obj)) != NULL) {
        bpf_map__unpin(map, NULL);
    }
    return libbpf_err(err);
}

int
bpf_object__unpin_maps(struct bpf_object* obj, const char* path)
{
    struct bpf_map* map;
    int err;

    if (!obj)
        return libbpf_err(-ENOENT);

    bpf_object__for_each_map(map, obj)
    {
        char* pin_path = NULL;
        char buf[PATH_MAX];

        if (path) {
            int len;

            len = snprintf(buf, PATH_MAX, "%s/%s", path, bpf_map__name(map));
            if (len < 0)
                return libbpf_err(-EINVAL);
            else if (len >= PATH_MAX)
                return libbpf_err(-ENAMETOOLONG);
            pin_path = buf;
        } else {
            continue;
        }

        err = bpf_map__unpin(map, pin_path);
        if (err)
            return libbpf_err(err);
    }

    return 0;
}

const char*
bpf_map__name(const struct bpf_map* map)
{
    return map ? map->name : NULL;
}

enum bpf_map_type
bpf_map__type(const struct bpf_map* map)
{
    return map->map_definition.type;
}

__u32
bpf_map__key_size(const struct bpf_map* map)
{
    return map->map_definition.key_size;
}

__u32
bpf_map__value_size(const struct bpf_map* map)
{
    return map->map_definition.value_size;
}

__u32
bpf_map__max_entries(const struct bpf_map* map)
{
    return map->map_definition.max_entries;
}

bool
bpf_map__is_pinned(const struct bpf_map* map)
{
    return map->pinned;
}

int
bpf_map__fd(const struct bpf_map* map)
{
    return map ? map->map_fd : libbpf_err(-EINVAL);
}
