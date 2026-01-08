// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf.h"
#include "ebpf_ring_buffer_record.h"
#include "ebpf_tracelog.h"
#include "libbpf.h"
#include "libbpf_internal.h"
#include "platform.h"

#include <windows.h>
#include <condition_variable>
#include <mutex>
#include <thread>

// This file implements APIs in LibBPF's libbpf.h and is based on code in external/libbpf/src/libbpf.c
// used under the BSD-2-Clause license , so the coding style tries to match the libbpf.c style to
// minimize diffs until libbpf becomes cross-platform capable.  This is a temporary workaround for
// issue #351 until we can compile and use libbpf.c directly.

// Shared mapping structure for ring direct access (synchronous mode).
struct ebpf_ring_mapping
{
    fd_t map_fd;
    void* sample_fn; // ring_buffer_sample_fn or perf_buffer_sample_fn
    void* ctx;
    ebpf_ring_buffer_consumer_page_t* consumer_page;
    const ebpf_ring_buffer_producer_page_t* producer_page;
    const uint8_t* data;
    uint64_t data_size;
};

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
    return (struct bpf_map*)libbpf_err_ptr(-ENOENT);
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
bpf_map_update_batch(int fd, const void* keys, const void* values, __u32* count, const struct bpf_map_batch_opts* opts)
{
    if (opts->flags != 0) {
        return libbpf_result_err(EBPF_INVALID_ARGUMENT);
    }
    return libbpf_result_err(ebpf_map_update_element_batch(fd, keys, values, count, opts->elem_flags));
}

int
bpf_map_delete_elem(int fd, const void* key)
{
    return libbpf_result_err(ebpf_map_delete_element(fd, key));
}

int
bpf_map_delete_batch(int fd, const void* keys, __u32* count, const struct bpf_map_batch_opts* opts)
{
    if (opts->flags != 0) {
        return libbpf_result_err(EBPF_INVALID_ARGUMENT);
    }
    return libbpf_result_err(ebpf_map_delete_element_batch(fd, keys, count, opts->elem_flags));
}

int
bpf_map_lookup_elem(int fd, const void* key, void* value)
{
    return libbpf_result_err(ebpf_map_lookup_element(fd, key, value));
}

int
bpf_map_lookup_batch(
    int fd,
    void* in_batch,
    void* out_batch,
    void* keys,
    void* values,
    __u32* count,
    const struct bpf_map_batch_opts* opts)
{
    if (opts->flags != 0) {
        return libbpf_result_err(EBPF_INVALID_ARGUMENT);
    }
    return libbpf_result_err(
        ebpf_map_lookup_element_batch(fd, in_batch, out_batch, keys, values, count, opts->elem_flags));
}

int
bpf_map_lookup_and_delete_elem(int fd, const void* key, void* value)
{
    return libbpf_result_err(ebpf_map_lookup_and_delete_element(fd, key, value));
}

int
bpf_map_lookup_and_delete_batch(
    int fd,
    void* in_batch,
    void* out_batch,
    void* keys,
    void* values,
    __u32* count,
    const struct bpf_map_batch_opts* opts)
{
    return libbpf_result_err(
        ebpf_map_lookup_and_delete_element_batch(fd, in_batch, out_batch, keys, values, count, opts->flags));
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
    std::vector<ebpf_map_subscription_t*> subscriptions;

    // Synchronous mode mapping info.
    std::vector<ebpf_ring_mapping> sync_maps;
    ebpf_handle_t wait_handle = ebpf_handle_invalid; // Single wait handle shared by all maps.

    bool is_async_mode = false; // True for async callbacks, false for sync processing.
} ring_buffer_t;

// Helper function to convert ring_buffer_opts to ebpf_ring_buffer_opts.
static inline struct ebpf_ring_buffer_opts
_convert_to_ebpf_opts(_In_ const struct ring_buffer_opts* linux_opts)
{
    // Linux ring buffer opts are currently empty (only sz field), so we use defaults (synchronous mode).
    ebpf_ring_buffer_opts ebpf_opts{.sz = sizeof(ebpf_opts), .flags = 0};
    UNREFERENCED_PARAMETER(linux_opts);
    return ebpf_opts;
}

// Helper function to convert perf_buffer_opts to ebpf_perf_buffer_opts.
static inline struct ebpf_perf_buffer_opts
_convert_to_ebpf_perf_opts(_In_ const struct perf_buffer_opts* linux_opts)
{
    // Linux perf buffer opts are currently empty (only sz field), so we use defaults (synchronous mode).
    ebpf_perf_buffer_opts ebpf_opts{.sz = sizeof(ebpf_opts), .flags = 0};
    UNREFERENCED_PARAMETER(linux_opts);
    return ebpf_opts;
}

// Helper function to process ring buffer records from memory pages.
static int
_process_ring_records(_In_ const ebpf_ring_mapping& mapping)
{
    if (!mapping.consumer_page || !mapping.producer_page || !mapping.data || !mapping.sample_fn) {
        return -EINVAL;
    }

    // Get current consumer and producer offsets from shared pages.
    uint64_t consumer_offset = ReadULong64Acquire(&mapping.consumer_page->consumer_offset);
    uint64_t producer_offset = ReadULong64Acquire(&mapping.producer_page->producer_offset);

    int records_processed = 0;
    const ebpf_ring_buffer_record_t* record{};
    // Process available records.
    while (nullptr !=
           (record = ebpf_ring_buffer_next_record(mapping.data, mapping.data_size, consumer_offset, producer_offset))) {
        // Check if record is locked (still being written by producer).
        if (ebpf_ring_buffer_record_is_locked(record)) {
            break; // Records must be read in order, so we stop here.
        }

        // Total bytes in record (including header + padding).
        uint32_t record_size = ebpf_ring_buffer_record_total_size(record);

        // Check if record is discarded (should be skipped).
        if (ebpf_ring_buffer_record_is_discarded(record)) {
            // Increment consumer_offset and update shared offset to return the space to the ring.
            consumer_offset += record_size;
            WriteULong64Release(&mapping.consumer_page->consumer_offset, consumer_offset);
        } else {
            uint32_t data_length = ebpf_ring_buffer_record_length(record);

            // Call the user callback with the record data.
            int result = ((ring_buffer_sample_fn)mapping.sample_fn)(mapping.ctx, (void*)record->data, data_length);
            if (result < 0) {
                // User callback requested to stop processing.
                break;
            }

            // Increment consumer_offset and update shared offset to return the space to the ring.
            consumer_offset += record_size;
            WriteULong64Release(&mapping.consumer_page->consumer_offset, consumer_offset);
            records_processed++;
        }

        if (consumer_offset >= producer_offset) {
            // Re-read producer offset to check for new data (but only if we need to).
            producer_offset = ReadULong64Acquire(&mapping.producer_page->producer_offset);
        }
    }

    return records_processed;
}

struct ring_buffer*
ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void* ctx, const struct ring_buffer_opts* opts)
{
    // Convert Linux opts to Windows opts with default synchronous behavior.
    auto ebpf_opts = _convert_to_ebpf_opts(opts);
    return ebpf_ring_buffer__new(map_fd, sample_cb, ctx, &ebpf_opts);
}

_Ret_maybenull_ struct ring_buffer*
ebpf_ring_buffer__new(
    int map_fd, ring_buffer_sample_fn sample_cb, _In_opt_ void* ctx, _In_opt_ const struct ebpf_ring_buffer_opts* opts)
    EBPF_NO_EXCEPT
{
    ebpf_result result = EBPF_SUCCESS;
    ring_buffer_t* local_ring_buffer = nullptr;

    if (sample_cb == nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    try {
        std::unique_ptr<ring_buffer_t> ring_buffer = std::make_unique<ring_buffer_t>();

        // Determine callback type based on flags.
        bool use_async_callbacks = opts != nullptr && (opts->flags & EBPF_RINGBUF_FLAG_AUTO_CALLBACK) != 0;

        ring_buffer->is_async_mode = use_async_callbacks;

        if (use_async_callbacks) {
            // Use the existing async callback mechanism.
            ebpf_map_subscription_t* subscription = nullptr;
            uint32_t cpu_id = 0;

            result = ebpf_map_subscribe(map_fd, &cpu_id, 1, ctx, (void*)sample_cb, nullptr, &subscription);

            if (result != EBPF_SUCCESS) {
                goto Exit;
            }

            try {
                ring_buffer->subscriptions.push_back(subscription);
            } catch (const std::bad_alloc&) {
                ebpf_map_unsubscribe(subscription);
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
        } else {
            // Set up for synchronous mode - create shared wait handle for all maps
            HANDLE wait_handle = CreateEvent(nullptr, TRUE, FALSE, nullptr);
            if (wait_handle == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            ring_buffer->wait_handle = reinterpret_cast<ebpf_handle_t>(wait_handle);

            // Set up the first map
            ebpf_ring_mapping map_info{};
            map_info.map_fd = map_fd;
            map_info.sample_fn = (void*)sample_cb;
            map_info.ctx = ctx;

            // Set the shared wait handle for this map to receive notifications
            result = ebpf_map_set_wait_handle(map_fd, 0, ring_buffer->wait_handle);
            if (result != EBPF_SUCCESS) {
                CloseHandle(wait_handle);
                ring_buffer->wait_handle = ebpf_handle_invalid;
                goto Exit;
            }

            // Get direct memory access to the ring buffer map
            result = ebpf_ring_buffer_map_map_buffer(
                map_fd,
                reinterpret_cast<void**>(&map_info.consumer_page),
                reinterpret_cast<const void**>(&map_info.producer_page),
                &map_info.data,
                &map_info.data_size);
            if (result != EBPF_SUCCESS) {
                CloseHandle(wait_handle);
                ring_buffer->wait_handle = ebpf_handle_invalid;
                goto Exit;
            }

            try {
                ring_buffer->sync_maps.push_back(map_info);
            } catch (const std::bad_alloc&) {
                CloseHandle(wait_handle);
                ring_buffer->wait_handle = ebpf_handle_invalid;
                (void)ebpf_ring_buffer_map_unmap_buffer(
                    map_fd, map_info.consumer_page, map_info.producer_page, map_info.data);
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
        }

        local_ring_buffer = ring_buffer.release();
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
Exit:
    if (result != EBPF_SUCCESS) {
        errno = ebpf_result_to_errno(result);
        EBPF_LOG_FUNCTION_ERROR(result);
    }
    EBPF_RETURN_POINTER(ring_buffer_t*, local_ring_buffer);
}

void
ring_buffer__free(struct ring_buffer* ring_buffer)
{
    if (!ring_buffer) {
        return;
    }

    // Clean up async subscriptions
    for (auto& subscription : ring_buffer->subscriptions) {
        ebpf_map_unsubscribe(subscription);
    }
    ring_buffer->subscriptions.clear();

    // Clean up sync map resources
    for (auto& map_info : ring_buffer->sync_maps) {
        (void)ebpf_ring_buffer_map_unmap_buffer(
            map_info.map_fd, map_info.consumer_page, map_info.producer_page, map_info.data);
    }
    ring_buffer->sync_maps.clear();

    // Clean up shared wait handle
    if (ring_buffer->wait_handle != ebpf_handle_invalid) {
        CloseHandle(reinterpret_cast<HANDLE>(ring_buffer->wait_handle));
        ring_buffer->wait_handle = ebpf_handle_invalid;
    }

    delete ring_buffer;
}

int
ring_buffer__add(struct ring_buffer* rb, int map_fd, ring_buffer_sample_fn sample_cb, void* ctx)
{
    if (!rb || map_fd < 0 || !sample_cb) {
        return -EINVAL;
    }

    if (rb->is_async_mode) {
        // Multiple subscriptions for async ring buffers not implemented.
        return -ENOTSUP;
    }

    // Add to sync mode - use the shared wait handle
    ebpf_ring_mapping map_info{};
    map_info.map_fd = map_fd;
    map_info.sample_fn = (void*)sample_cb;
    map_info.ctx = ctx;

    // Set the shared wait handle for this map to receive notifications
    ebpf_result_t result = ebpf_map_set_wait_handle(map_fd, 0, rb->wait_handle);
    if (result != EBPF_SUCCESS) {
        return -ebpf_result_to_errno(result);
    }

    // Get direct memory access to the ring buffer map
    result = ebpf_ring_buffer_map_map_buffer(
        map_fd,
        reinterpret_cast<void**>(&map_info.consumer_page),
        reinterpret_cast<const void**>(&map_info.producer_page),
        &map_info.data,
        &map_info.data_size);
    if (result != EBPF_SUCCESS) {
        (void)ebpf_map_set_wait_handle(map_fd, 0, ebpf_handle_invalid);
        return -ebpf_result_to_errno(result);
    }

    try {
        rb->sync_maps.push_back(map_info);
        return 0;
    } catch (const std::bad_alloc&) {
        (void)ebpf_map_set_wait_handle(map_fd, 0, ebpf_handle_invalid);
        (void)ebpf_ring_buffer_map_unmap_buffer(map_fd, map_info.consumer_page, map_info.producer_page, map_info.data);
        return -ENOMEM;
    }
}

int
ring_buffer__poll(struct ring_buffer* rb, int timeout_ms)
{
    // For async mode, polling doesn't make sense since callbacks are automatic.
    if (!rb || rb->sync_maps.empty() || rb->is_async_mode) {
        return -EINVAL;
    }

    // First, try to consume any immediately available data.
    int result = ring_buffer__consume(rb);
    if (result != 0 || timeout_ms == 0) {                      // Return records found or error.
        ResetEvent(reinterpret_cast<HANDLE>(rb->wait_handle)); // Reset event for next poll.
        return result;
    }

    // Wait for notification or timeout.
    DWORD wait_result = WaitForSingleObject(
        reinterpret_cast<HANDLE>(rb->wait_handle), timeout_ms < 0 ? INFINITE : static_cast<DWORD>(timeout_ms));
    if (wait_result == WAIT_OBJECT_0) {
        result = ring_buffer__consume(rb);
        ResetEvent(reinterpret_cast<HANDLE>(rb->wait_handle)); // Reset event for next poll.
    } else if (wait_result != WAIT_TIMEOUT) {
        result = -EINVAL; // Failed to wait, return error.
    } // Else timeout occurred, return 0.

    return result;
}

int
ring_buffer__consume(struct ring_buffer* rb)
{
    if (!rb || rb->sync_maps.empty() || rb->is_async_mode) {
        return -EINVAL;
    }

    int total_records = 0;
    // Process all available data from all ring buffers
    for (const auto& map_info : rb->sync_maps) {
        int result = _process_ring_records(map_info); // Process all records
        if (result < 0) {
            return result; // Return error
        }
        total_records += result;
    }

    return total_records;
}

ebpf_handle_t
ebpf_ring_buffer_get_wait_handle(_In_ struct ring_buffer* rb) EBPF_NO_EXCEPT
{
    if (!rb) {
        return ebpf_handle_invalid;
    }

    if (rb->is_async_mode) {
        // For async mode, the wait handle is not currently set.
        return ebpf_handle_invalid;
    }

    return rb->wait_handle;
}

_Must_inspect_result_ _Success_(return == EBPF_SUCCESS) ebpf_result_t ebpf_ring_buffer_get_buffer(
    _In_ struct ring_buffer* rb,
    _In_ uint32_t index,
    _Outptr_result_maybenull_ ebpf_ring_buffer_consumer_page_t** consumer_page,
    _Outptr_result_maybenull_ const ebpf_ring_buffer_producer_page_t** producer_page,
    _Outptr_result_buffer_maybenull_(*data_size) const uint8_t** data,
    _Out_opt_ uint64_t* data_size) EBPF_NO_EXCEPT
{
    if (!rb || !consumer_page || !producer_page || !data || !data_size) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (rb->is_async_mode) {
        // For async mode, direct buffer access isn't currently supported.
        return EBPF_INVALID_ARGUMENT;
    }

    if (index >= rb->sync_maps.size()) {
        return EBPF_OBJECT_NOT_FOUND;
    }

    // Return buffer info for the specified map
    const auto& map_info = rb->sync_maps[index];
    *consumer_page = static_cast<ebpf_ring_buffer_consumer_page_t*>(map_info.consumer_page);
    *producer_page = static_cast<const ebpf_ring_buffer_producer_page_t*>(map_info.producer_page);
    *data = map_info.data;
    *data_size = map_info.data_size;

    return EBPF_SUCCESS;
}

const char*
libbpf_bpf_map_type_str(enum bpf_map_type t)
{
    if (t < 0 || t >= _countof(_ebpf_map_display_names)) {
        return nullptr;
    }

    return _ebpf_map_display_names[t];
}

typedef struct perf_buffer
{
    std::vector<ebpf_map_subscription_t*> subscriptions;
} perf_buffer_t;

struct perf_buffer*
perf_buffer__new(
    int map_fd,
    size_t page_cnt,
    perf_buffer_sample_fn sample_cb,
    perf_buffer_lost_fn lost_cb,
    void* ctx,
    const struct perf_buffer_opts* opts)
{
    // Convert Linux opts to Windows opts with default synchronous behavior.
    auto ebpf_opts = _convert_to_ebpf_perf_opts(opts);
    return ebpf_perf_buffer__new(map_fd, page_cnt, sample_cb, lost_cb, ctx, &ebpf_opts);
}

_Ret_maybenull_ struct perf_buffer*
ebpf_perf_buffer__new(
    int map_fd,
    size_t page_cnt,
    perf_buffer_sample_fn sample_cb,
    perf_buffer_lost_fn lost_cb,
    _In_opt_ void* ctx,
    _In_opt_ const struct ebpf_perf_buffer_opts* opts) EBPF_NO_EXCEPT
{
    ebpf_result result = EBPF_SUCCESS;
    perf_buffer_t* local_perf_buffer = nullptr;
    std::vector<uint32_t> cpu_ids;

    if ((sample_cb == nullptr) || (lost_cb == nullptr)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (page_cnt != 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    try {
        bool use_async_callbacks = opts != nullptr && (opts->flags & EBPF_PERFBUF_FLAG_AUTO_CALLBACK) != 0;
        if (!use_async_callbacks) {
            result = EBPF_OPERATION_NOT_SUPPORTED;
            goto Exit;
        }

        std::unique_ptr<perf_buffer_t> perf_buffer = std::make_unique<perf_buffer_t>();
        uint32_t ring_count = libbpf_num_possible_cpus();
        ebpf_map_subscription_t* subscription = nullptr;

        for (uint32_t cpu_id = 0; cpu_id < ring_count; cpu_id++) {
            cpu_ids.push_back(cpu_id);
        }

        result = ebpf_map_subscribe(
            map_fd, cpu_ids.data(), cpu_ids.size(), ctx, (void*)sample_cb, (void*)lost_cb, &subscription);

        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        try {
            perf_buffer->subscriptions.push_back(subscription);
        } catch (const std::bad_alloc&) {
            ebpf_map_unsubscribe(subscription);
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        local_perf_buffer = perf_buffer.release();
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
Exit:
    if (result != EBPF_SUCCESS) {
        errno = ebpf_result_to_errno(result);
        EBPF_LOG_FUNCTION_ERROR(result);
    }
    EBPF_RETURN_POINTER(perf_buffer*, local_perf_buffer);
}

void
perf_buffer__free(struct perf_buffer* pb)
{
    for (auto& subscription : pb->subscriptions) {
        ebpf_map_unsubscribe(subscription);
    }

    pb->subscriptions.clear();
    delete pb;
}
