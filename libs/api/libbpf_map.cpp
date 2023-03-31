// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

// This file implements APIs in LibBPF's libbpf.h and is based on code in external/libbpf/src/libbpf.c
// used under the BSD-2-Clause license , so the coding style tries to match the libbpf.c style to
// minimize diffs until libbpf becomes cross-platform capable.  This is a temporary workaround for
// issue #351 until we can compile and use libbpf.c directly.

int
bpf_map_create(
    enum bpf_map_type map_type,
    const char* map_name,
    __u32 key_size,
    __u32 value_size,
    __u32 max_entries,
    const struct bpf_map_create_opts* opts)
{
    fd_t map_fd;
    ebpf_result_t result = ebpf_map_create(map_type, map_name, key_size, value_size, max_entries, opts, &map_fd);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }
    return map_fd;
}

int
bpf_create_map_xattr(const struct bpf_create_map_attr* create_attr)
{
    LIBBPF_OPTS(bpf_map_create_opts, p);

    p.map_flags = create_attr->map_flags;
    p.numa_node = create_attr->numa_node;
    p.btf_fd = create_attr->btf_fd;
    p.btf_key_type_id = create_attr->btf_key_type_id;
    p.btf_value_type_id = create_attr->btf_value_type_id;
    p.map_ifindex = create_attr->map_ifindex;
    p.inner_map_fd = create_attr->inner_map_fd;

    return bpf_map_create(
        create_attr->map_type,
        create_attr->name,
        create_attr->key_size,
        create_attr->value_size,
        create_attr->max_entries,
        &p);
}

int
bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, uint32_t map_flags)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = map_flags);

    return bpf_map_create(map_type, NULL, key_size, value_size, max_entries, &opts);
}

int
bpf_create_map_in_map(
    enum bpf_map_type map_type, const char* name, int key_size, int inner_map_fd, int max_entries, __u32 map_flags)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts, .inner_map_fd = (uint32_t)inner_map_fd, .map_flags = map_flags, );

    return bpf_map_create(map_type, name, key_size, 4, max_entries, &opts);
}

struct bpf_map*
bpf_map__next(const struct bpf_map* prev, const struct bpf_object* obj)
{
    return bpf_object__next_map(obj, prev);
}

struct bpf_map*
bpf_object__next_map(const struct bpf_object* object, const struct bpf_map* previous)
{
    return ebpf_map_next(previous, object);
}

struct bpf_map*
bpf_map__prev(const struct bpf_map* next, const struct bpf_object* obj)
{
    return bpf_object__prev_map(obj, next);
}

struct bpf_map*
bpf_object__prev_map(const struct bpf_object* object, const struct bpf_map* next)
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

    if (!obj) {
        return libbpf_err(-ENOENT);
    }

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
        if (err) {
            goto err_unpin_maps;
        }
    }

    return 0;

err_unpin_maps:
    while ((map = bpf_object__prev_map(obj, map)) != NULL) {
        bpf_map__unpin(map, NULL);
    }
    return libbpf_err(err);
}

int
bpf_object__unpin_maps(struct bpf_object* obj, const char* path)
{
    struct bpf_map* map;
    int err;

    if (!obj) {
        return libbpf_err(-ENOENT);
    }

    bpf_object__for_each_map(map, obj)
    {
        char* pin_path = NULL;
        char buf[PATH_MAX];

        if (path) {
            int len;

            len = snprintf(buf, PATH_MAX, "%s/%s", path, bpf_map__name(map));
            if (len < 0) {
                return libbpf_err(-EINVAL);
            } else if (len >= PATH_MAX) {
                return libbpf_err(-ENAMETOOLONG);
            }
            pin_path = buf;
        } else {
            continue;
        }

        err = bpf_map__unpin(map, pin_path);
        if (err) {
            return libbpf_err(err);
        }
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
        if (pos->name && !strcmp(pos->name, name)) {
            return pos;
        }
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
bpf_map_lookup_and_delete_elem(int fd, const void* key, void* value)
{
    return libbpf_result_err(ebpf_map_lookup_and_delete_element(fd, key, value));
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

typedef struct ring_buffer
{
    std::vector<ring_buffer_subscription_t*> subscriptions;
} ring_buffer_t;

struct ring_buffer*
ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void* ctx, const struct ring_buffer_opts* /* opts */)
{
    ebpf_result result = EBPF_SUCCESS;
    ring_buffer_t* local_ring_buffer = nullptr;

    try {
        std::unique_ptr<ring_buffer_t> ring_buffer = std::make_unique<ring_buffer_t>();
        ring_buffer_subscription_t* subscription = nullptr;
        result = ebpf_ring_buffer_map_subscribe(map_fd, ctx, sample_cb, &subscription);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
        ring_buffer->subscriptions.push_back(subscription);
        local_ring_buffer = ring_buffer.release();
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
Exit:
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_FUNCTION_ERROR(result);
    }
    EBPF_RETURN_POINTER(ring_buffer_t*, local_ring_buffer);
}

void
ring_buffer__free(struct ring_buffer* ring_buffer)
{
    for (auto it = ring_buffer->subscriptions.begin(); it != ring_buffer->subscriptions.end(); it++) {
        (void)ebpf_ring_buffer_map_unsubscribe(*it);
    }
    ring_buffer->subscriptions.clear();
    delete ring_buffer;
}

const char*
libbpf_bpf_map_type_str(enum bpf_map_type t)
{
    if (t < 0 || t >= _countof(_ebpf_map_display_names)) {
        return nullptr;
    }

    return _ebpf_map_display_names[t];
}
