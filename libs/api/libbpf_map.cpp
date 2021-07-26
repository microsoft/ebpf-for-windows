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
    char fullpath[MAX_PATH];
    int length = snprintf(fullpath, sizeof(fullpath), "%s/%s", path, map->name);
    if (length < 0) {
        return -EINVAL;
    } else if (length > sizeof(fullpath)) {
        return -ENAMETOOLONG;
    }

    uint32_t result = ebpf_api_unpin_object((const uint8_t*)fullpath, (uint32_t)strlen(fullpath));
    if (result) {
        return libbpf_err(result);
    }

    // TODO(issue #81): ebpf_api_unpin_object should set this.
    map->pinned = false;

    return 0;
}

static void
_unpin_previous_maps(_In_ ebpf_map_t* map, _In_ struct bpf_object* object, const char* path)
{
    for (map = bpf_map__prev(map, object); map; map = bpf_map__prev(map, object)) {
        bpf_map__unpin(map, path);
    }
}

int
bpf_map__pin(struct bpf_map* map, const char* path)
{
    char fullpath[MAX_PATH];

    int length = snprintf(fullpath, sizeof(fullpath), "%s/%s", path, map->name);
    if (length < 0) {
        return libbpf_err(-EINVAL);
    }

    int result = ebpf_api_pin_object(map->map_handle, (const uint8_t*)fullpath, (uint32_t)strlen(fullpath));
    if (result) {
        return libbpf_err(result);
    }

    // TODO(issue #81): ebpf_api_pin_object should set this.
    map->pinned = true;

    return 0;
}

int
bpf_object__pin_maps(struct bpf_object* object, const char* path)
{
    struct bpf_map* map;

    if (!object) {
        return libbpf_err(-ENOENT);
    }

    bpf_object__for_each_map(map, object)
    {
        int result = bpf_map__pin(map, path);
        if (result) {
            _unpin_previous_maps(map, object, path);
            return result;
        }
    }

    return 0;
}

int
bpf_object__unpin_maps(struct bpf_object* object, const char* path)
{
    struct bpf_map* map;

    if (!object) {
        return libbpf_err(-ENOENT);
    }

    bpf_object__for_each_map(map, object)
    {
        int result = bpf_map__unpin(map, path);
        if (result) {
            return libbpf_err(result);
        }
    }

    return 0;
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
