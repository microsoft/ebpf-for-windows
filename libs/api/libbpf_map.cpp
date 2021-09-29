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

int
bpf_create_map_xattr(const struct bpf_create_map_attr* create_attr)
{
    fd_t map_fd;
    ebpf_result_t result = ebpf_create_map_xattr(create_attr, &map_fd);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }
    return map_fd;
}

int
bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, uint32_t map_flags)
{
    struct bpf_create_map_attr map_attr = {0};

    map_attr.map_type = map_type;
    map_attr.map_flags = map_flags;
    map_attr.key_size = key_size;
    map_attr.value_size = value_size;
    map_attr.max_entries = max_entries;

    return bpf_create_map_xattr(&map_attr);
}

int
bpf_create_map_in_map(
    enum bpf_map_type map_type, const char* name, int key_size, int inner_map_fd, int max_entries, __u32 map_flags)
{
    struct bpf_create_map_attr map_attr = {0};

    map_attr.map_type = map_type;
    map_attr.name = name;
    map_attr.key_size = key_size;
    map_attr.value_size = sizeof(ebpf_id_t);
    map_attr.inner_map_fd = inner_map_fd;
    map_attr.max_entries = max_entries;
    map_attr.map_flags = map_flags;

    return bpf_create_map_xattr(&map_attr);
}

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
    return libbpf_result_err(ebpf_map_unpin(map, path));
}

int
bpf_map__pin(struct bpf_map* map, const char* path)
{
    return libbpf_result_err(ebpf_map_pin(map, path));
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

struct bpf_map*
bpf_object__find_map_by_name(const struct bpf_object* obj, const char* name)
{
    struct bpf_map* pos;

    bpf_object__for_each_map(pos, obj)
    {
        if (pos->name && !strcmp(pos->name, name))
            return pos;
    }
    return NULL;
}

int
bpf_object__find_map_fd_by_name(const struct bpf_object* obj, const char* name)
{
    return bpf_map__fd(bpf_object__find_map_by_name(obj, name));
}

int
bpf_map__set_pin_path(struct bpf_map* map, const char* path)
{
    return libbpf_result_err(ebpf_map_set_pin_path(map, path));
}

int
bpf_map_update_elem(int fd, const void* key, const void* value, uint64_t flags)
{
    return libbpf_result_err(ebpf_map_update_element(fd, key, value, flags));
}

int
bpf_map_delete_elem(int fd, const void* key)
{
    return libbpf_result_err(ebpf_map_delete_element(fd, key));
}

int
bpf_map_lookup_elem(int fd, const void* key, void* value)
{
    return libbpf_result_err(ebpf_map_lookup_element(fd, key, value));
}

int
bpf_map_get_next_key(int fd, const void* key, void* next_key)
{
    return libbpf_result_err(ebpf_map_get_next_key(fd, key, next_key));
}

int
bpf_map_get_fd_by_id(uint32_t id)
{
    fd_t fd;
    ebpf_result_t result = ebpf_get_map_fd_by_id(id, &fd);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }
    return fd;
}

int
bpf_map_get_next_id(uint32_t start_id, uint32_t* next_id)
{
    return libbpf_result_err(ebpf_get_next_map_id(start_id, next_id));
}
