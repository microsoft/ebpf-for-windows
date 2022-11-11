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

static int
_bpf_map_create(
    enum bpf_map_type map_type,
    const char* map_name,
    __u32 key_size,
    __u32 value_size,
    __u32 max_entries,
    const struct bpf_map_create_opts* opts) noexcept
{
    fd_t map_fd;
    ebpf_result_t result = ebpf_map_create(map_type, map_name, key_size, value_size, max_entries, opts, &map_fd);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }
    return map_fd;
}

int
bpf_map_create(
    enum bpf_map_type map_type,
    const char* map_name,
    __u32 key_size,
    __u32 value_size,
    __u32 max_entries,
    const struct bpf_map_create_opts* opts)
{
    return _bpf_map_create(map_type, map_name, key_size, value_size, max_entries, opts);
}

static int
_bpf_create_map_xattr(const struct bpf_create_map_attr* create_attr) noexcept
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
bpf_create_map_xattr(const struct bpf_create_map_attr* create_attr)
{
    return _bpf_create_map_xattr(create_attr);
}

static int
_bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, uint32_t map_flags) noexcept
{
    LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = map_flags);

    return bpf_map_create(map_type, NULL, key_size, value_size, max_entries, &opts);
}

int
bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, uint32_t map_flags)
{
    return _bpf_create_map(map_type, key_size, value_size, max_entries, map_flags);
}

static int
_bpf_create_map_in_map(
    enum bpf_map_type map_type,
    const char* name,
    int key_size,
    int inner_map_fd,
    int max_entries,
    __u32 map_flags) noexcept
{
    LIBBPF_OPTS(bpf_map_create_opts, opts, .inner_map_fd = (uint32_t)inner_map_fd, .map_flags = map_flags, );

    return bpf_map_create(map_type, name, key_size, 4, max_entries, &opts);
}

int
bpf_create_map_in_map(
    enum bpf_map_type map_type, const char* name, int key_size, int inner_map_fd, int max_entries, __u32 map_flags)
{
    return _bpf_create_map_in_map(map_type, name, key_size, inner_map_fd, max_entries, map_flags);
}

static struct bpf_map*
_bpf_map__next(const struct bpf_map* prev, const struct bpf_object* obj) noexcept
{
    return bpf_object__next_map(obj, prev);
}

struct bpf_map*
bpf_map__next(const struct bpf_map* prev, const struct bpf_object* obj)
{
    return _bpf_map__next(prev, obj);
}

static struct bpf_map*
_bpf_object__next_map(const struct bpf_object* object, const struct bpf_map* previous) noexcept
{
    return ebpf_map_next(previous, object);
}

struct bpf_map*
bpf_object__next_map(const struct bpf_object* object, const struct bpf_map* previous)
{
    return _bpf_object__next_map(object, previous);
}

static struct bpf_map*
_bpf_map__prev(const struct bpf_map* next, const struct bpf_object* obj) noexcept
{
    return bpf_object__prev_map(obj, next);
}

struct bpf_map*
bpf_map__prev(const struct bpf_map* next, const struct bpf_object* obj)
{
    return _bpf_map__prev(next, obj);
}

static struct bpf_map*
_bpf_object__prev_map(const struct bpf_object* object, const struct bpf_map* next) noexcept
{
    return ebpf_map_previous(next, object);
}

struct bpf_map*
bpf_object__prev_map(const struct bpf_object* object, const struct bpf_map* next)
{
    return _bpf_object__prev_map(object, next);
}

static int
_bpf_map__unpin(struct bpf_map* map, const char* path) noexcept
{
    return libbpf_result_err(ebpf_map_unpin(map, path));
}

int
bpf_map__unpin(struct bpf_map* map, const char* path)
{
    return _bpf_map__unpin(map, path);
}

static int
_bpf_map__pin(struct bpf_map* map, const char* path) noexcept
{
    return libbpf_result_err(ebpf_map_pin(map, path));
}

int
bpf_map__pin(struct bpf_map* map, const char* path)
{
    return _bpf_map__pin(map, path);
}

static int
_bpf_object__pin_maps(struct bpf_object* obj, const char* path) noexcept
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
    while ((map = bpf_object__prev_map(obj, map)) != NULL) {
        bpf_map__unpin(map, NULL);
    }
    return libbpf_err(err);
}

int
bpf_object__pin_maps(struct bpf_object* obj, const char* path)
{
    return _bpf_object__pin_maps(obj, path);
}

static int
_bpf_object__unpin_maps(struct bpf_object* obj, const char* path) noexcept
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

int
bpf_object__unpin_maps(struct bpf_object* obj, const char* path)
{
    return _bpf_object__unpin_maps(obj, path);
}

static const char*
_bpf_map__name(const struct bpf_map* map) noexcept
{
    return map ? map->name : NULL;
}

const char*
bpf_map__name(const struct bpf_map* map)
{
    return _bpf_map__name(map);
}

static enum bpf_map_type
_bpf_map__type(const struct bpf_map* map) noexcept
{
    return map->map_definition.type;
}

enum bpf_map_type
bpf_map__type(const struct bpf_map* map)
{
    return _bpf_map__type(map);
}

static __u32
_bpf_map__key_size(const struct bpf_map* map) noexcept
{
    return map->map_definition.key_size;
}

__u32
bpf_map__key_size(const struct bpf_map* map)
{
    return _bpf_map__key_size(map);
}

static __u32
_bpf_map__value_size(const struct bpf_map* map) noexcept
{
    return map->map_definition.value_size;
}

__u32
bpf_map__value_size(const struct bpf_map* map)
{
    return _bpf_map__value_size(map);
}

static __u32
_bpf_map__max_entries(const struct bpf_map* map) noexcept
{
    return map->map_definition.max_entries;
}

__u32
bpf_map__max_entries(const struct bpf_map* map)
{
    return _bpf_map__max_entries(map);
}

static bool
_bpf_map__is_pinned(const struct bpf_map* map) noexcept
{
    return map->pinned;
}

bool
bpf_map__is_pinned(const struct bpf_map* map)
{
    return _bpf_map__is_pinned(map);
}

static int
_bpf_map__fd(const struct bpf_map* map) noexcept
{
    return map ? map->map_fd : libbpf_err(-EINVAL);
}

int
bpf_map__fd(const struct bpf_map* map)
{
    return _bpf_map__fd(map);
}

static struct bpf_map*
_bpf_object__find_map_by_name(const struct bpf_object* obj, const char* name) noexcept
{
    struct bpf_map* pos;

    bpf_object__for_each_map(pos, obj)
    {
        if (pos->name && !strcmp(pos->name, name))
            return pos;
    }
    return NULL;
}

struct bpf_map*
bpf_object__find_map_by_name(const struct bpf_object* obj, const char* name)
{
    return _bpf_object__find_map_by_name(obj, name);
}

static int
_bpf_object__find_map_fd_by_name(const struct bpf_object* obj, const char* name) noexcept
{
    return bpf_map__fd(bpf_object__find_map_by_name(obj, name));
}

int
bpf_object__find_map_fd_by_name(const struct bpf_object* obj, const char* name)
{
    return _bpf_object__find_map_fd_by_name(obj, name);
}

static int
_bpf_map__set_pin_path(struct bpf_map* map, const char* path) noexcept
{
    return libbpf_result_err(ebpf_map_set_pin_path(map, path));
}

int
bpf_map__set_pin_path(struct bpf_map* map, const char* path)
{
    return _bpf_map__set_pin_path(map, path);
}

static int
_bpf_map_update_elem(int fd, const void* key, const void* value, uint64_t flags) noexcept
{
    return libbpf_result_err(ebpf_map_update_element(fd, key, value, flags));
}

int
bpf_map_update_elem(int fd, const void* key, const void* value, uint64_t flags)
{
    return _bpf_map_update_elem(fd, key, value, flags);
}

static int
_bpf_map_delete_elem(int fd, const void* key) noexcept
{
    return libbpf_result_err(ebpf_map_delete_element(fd, key));
}

int
bpf_map_delete_elem(int fd, const void* key)
{
    return _bpf_map_delete_elem(fd, key);
}

static int
_bpf_map_lookup_elem(int fd, const void* key, void* value) noexcept
{
    return libbpf_result_err(ebpf_map_lookup_element(fd, key, value));
}

int
bpf_map_lookup_elem(int fd, const void* key, void* value)
{
    return _bpf_map_lookup_elem(fd, key, value);
}

static int
_bpf_map_lookup_and_delete_elem(int fd, const void* key, void* value) noexcept
{
    return libbpf_result_err(ebpf_map_lookup_and_delete_element(fd, key, value));
}

int
bpf_map_lookup_and_delete_elem(int fd, const void* key, void* value)
{
    return _bpf_map_lookup_and_delete_elem(fd, key, value);
}

static int
_bpf_map_get_next_key(int fd, const void* key, void* next_key) noexcept
{
    return libbpf_result_err(ebpf_map_get_next_key(fd, key, next_key));
}

int
bpf_map_get_next_key(int fd, const void* key, void* next_key)
{
    return _bpf_map_get_next_key(fd, key, next_key);
}

static int
_bpf_map_get_fd_by_id(uint32_t id) noexcept
{
    fd_t fd;
    ebpf_result_t result = ebpf_get_map_fd_by_id(id, &fd);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }
    return fd;
}

int
bpf_map_get_fd_by_id(uint32_t id)
{
    return _bpf_map_get_fd_by_id(id);
}

static int
_bpf_map_get_next_id(uint32_t start_id, uint32_t* next_id) noexcept
{
    return libbpf_result_err(ebpf_get_next_map_id(start_id, next_id));
}

int
bpf_map_get_next_id(uint32_t start_id, uint32_t* next_id)
{
    return _bpf_map_get_next_id(start_id, next_id);
}

typedef struct ring_buffer
{
    std::vector<ring_buffer_subscription_t*> subscriptions;
} ring_buffer_t;

static struct ring_buffer*
_ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void* ctx, const struct ring_buffer_opts* opts) noexcept
{
    ebpf_result result = EBPF_SUCCESS;
    ring_buffer_subscription_t* subscription = nullptr;
    UNREFERENCED_PARAMETER(opts);
    ring_buffer_t* ring_buffer = new ring_buffer_t();
    if (ring_buffer == nullptr)
        goto Exit;
    result = ebpf_ring_buffer_map_subscribe(map_fd, ctx, sample_cb, &subscription);
    if (result != EBPF_SUCCESS)
        goto Exit;
    ring_buffer->subscriptions.push_back(subscription);
Exit:
    return ring_buffer;
}

struct ring_buffer*
ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void* ctx, const struct ring_buffer_opts* opts)
{
    return _ring_buffer__new(map_fd, sample_cb, ctx, opts);
}

static void
_ring_buffer__free(struct ring_buffer* ring_buffer) noexcept
{
    for (auto it = ring_buffer->subscriptions.begin(); it != ring_buffer->subscriptions.end(); it++)
        (void)ebpf_ring_buffer_map_unsubscribe(*it);
    ring_buffer->subscriptions.clear();
    delete ring_buffer;
}

void
ring_buffer__free(struct ring_buffer* ring_buffer)
{
    _ring_buffer__free(ring_buffer);
}

static const char*
_libbpf_bpf_map_type_str(enum bpf_map_type t) noexcept
{
    if (t < 0 || t >= _countof(_ebpf_map_display_names))
        return nullptr;

    return _ebpf_map_display_names[t];
}

const char*
libbpf_bpf_map_type_str(enum bpf_map_type t)
{
    return _libbpf_bpf_map_type_str(t);
}