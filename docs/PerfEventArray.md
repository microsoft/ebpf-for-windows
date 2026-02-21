# Perf Event Array

This document describes the support for the bpf map type BPF_MAP_TYPE_PERF_EVENT_ARRAY.

NOTE: With [#4640](https://github.com/microsoft/ebpf-for-windows/pull/4640) The default behavior has been changed to be Linux-compatible.
- Code expecting asynchronous callbacks should switch to `ebpf_perf_buffer__new` with `EBPF_PERFBUF_FLAG_AUTO_CALLBACK` set in the opts flags.

## Background

On Linux there are two map types for sending large amounts of data from BPF programs to user space.

The older one is the perf event array, which on Linux interfaces with the Linux perf subsystem to provide
per-CPU ring buffers. The perf subsystem has many other features (including counters and hardware event support)
and some of them are exposed via bpf.

The newer option is the ring buffer map, which is a single ring buffer (not per-CPU).

There are 3 primary differences between ring buffer maps and perf event arrays:

  1. Perf event arrays are per-CPU, whereas ring buffers are a single shared buffer.
      - Currently on Linux perf_event_output may only write to the current CPU,
        and manually specifying a CPU other than the currently running one will return an error.
      - By default the consumer attaches to all CPUs to get events from each per-CPU buffer.
      - Using `perf_buffer__new_raw` a consumer can attach to specific CPUs
  2. Ring buffer maps support reserve and submit to separately allocate and then fill in the record.
  3. For supported program types with a payload, perf event arrays can copy payload from the bpf context by
  putting the length to copy in the `BPF_F_CTXLEN_MASK` field of the flags.
      - `perf_event_output` takes the bpf context as an argument and the helper implementation copies the payload.
          - The payload is whatever the data pointer of the program context points to (e.g. packet data including headers). The payload does not include the bpf program context structure itself.

The main motivation for this implementation is to efficiently support payload capture from the context in eBPF programs.
- Supporting ring buffer reserve and submit in ebpf-for-windows is currently blocked on verifier support [#273](https://github.com/vbpf/ebpf-verifier/issues/273).
- Without reserve+submit, using `ringbuf_output` for payload capture requires using a per-CPU array as scratch space to append the payload to the event before calling ringbuf_output.
- The CTXLEN field in the flags of `perf_event_output` tells the kernel to append bytes from the payload to the record, avoiding the extra copy.
  - On Linux this works for specific program types, on Windows this works for any program type with a data pointer in the context.


The perf buffers are implemented using the ring buffer map support in ebpf-for-windows.

## Features

### Map Type: BPF_MAP_TYPE_PERF_EVENT_ARRAY

1. **Linux-compatible default behavior**
   - By default uses synchronous callbacks.
2. **Perf ring buffer support** (not other Linux perf features)
   - Supports eBPF program producers with a single user-space consumer per event array.
   - **Not supported**: perf counters, hardware-generated perf events, attaching eBPF programs to perf events, and sending events from user-space to eBPF programs.
3. **Asynchronous callbacks** (Windows-specific)
   - In addition to the Linux behavior, automatically invokes the callback if the `EBPF_PERFBUF_FLAG_AUTO_CALLBACK` flag is set.

### Helper Function: bpf_perf_event_output

1. **Current CPU writes only** (matches current Linux restrictions)
   - Specify current CPU in flags using `BPF_F_INDEX_MASK` or pass `BPF_F_CURRENT_CPU`.
2. **BPF_F_CTXLEN_MASK support** for any eBPF program types with a data pointer in the context
   - The global helper copies the memory from the program-type specific context data pointer, so no extension-specific helpers are needed.
   - The extension-provided `ebpf_context_descriptor_t` includes the offset of the data pointer.
   - Passing a non-zero value in `BPF_F_CTXLEN_MASK` returns an operation not supported error for program types without a data pointer in the context.

### libbpf Support

1. **`perf_buffer__new`** - Create a new perfbuf manager (Linux-compatible, synchronous mode consumer).
   - Attaches to all CPUs automatically.
   - Uses synchronous callbacks to match Linux libbpf behavior.
2. **`perf_buffer__free`** - Free perfbuf manager (detaches callback).
3. **`perf_buffer__poll`** - Poll perf buffers for new data with timeout (synchronous mode).
4. **`perf_buffer__consume`** - Consume available records without waiting (synchronous mode).
5. **`perf_buffer__consume_buffer`** - Consume records from a specific per-CPU buffer.
6. **`perf_buffer__buffer_cnt`** - Get the number of per-CPU buffers.
7. **`ebpf_perf_buffer__new`** - Windows-specific perfbuf manager with flags for async/sync modes.
8. **`ebpf_perf_buffer_get_wait_handle`** - Get wait handle for blocking on new data (Windows-specific).

## Consumer Modes

Similar to ring buffers, perf event arrays support both synchronous and asynchronous consumer modes.

ebpf-for-windows now uses Linux-compatible synchronous callbacks by default, with the existing asynchronous callbacks supported via the `EBPF_PERFBUF_FLAG_AUTO_CALLBACK` flag.

Linux only supports synchronous perf buffer consumers using either the libbpf interface or directly
accessing the shared memory, with epoll to wait for new data. ebpf-for-windows supports synchronous callbacks (like libbpf on Linux) and wait handle access, while also preserving asynchronous callback support as a Windows-specific feature.

### Usage Patterns

**Synchronous callback consumer (Linux-compatible):**

1. Call `perf_buffer__new` to set up callback (uses synchronous mode by default to match Linux).
   - Or call `ebpf_perf_buffer__new` without `EBPF_PERFBUF_FLAG_AUTO_CALLBACK` set in flags.
2. Call `perf_buffer__poll()` to wait for data if needed and invoke the callback on all available records.
3. Call `perf_buffer__consume()` to consume available records without waiting.

**Asynchronous callback consumer (Windows-specific):**

1. Call `ebpf_perf_buffer__new` with `EBPF_PERFBUF_FLAG_AUTO_CALLBACK` specified.
   - Note: automatic callbacks were the original default behavior, but the default has been changed to be source-compatible with Linux.
2. The callback will be invoked automatically for each record written to any per-CPU buffer.

**Wait handle consumer (Windows-specific):**

1. Call `perf_buffer__new` or `ebpf_perf_buffer__new` to create the perf buffer.
2. Call `ebpf_perf_buffer_get_wait_handle` to get the wait handle.
3. Call `WaitForSingleObject`/`WaitForMultipleObject` as needed to wait for new data to be available.
4. Call `perf_buffer__consume()` to process available records.

### Differences from Linux API

#### Poll and Consume

On Linux `perf_buffer__poll()` and `perf_buffer__consume()` are used to invoke the callback.
`poll()` waits for available data (or until timeout), then consumes all available records.
`consume()` consumes all available records (without waiting).

Windows now supports both `perf_buffer__poll()` and `perf_buffer__consume()`, with Linux-compatible behavior.
`perf_buffer__consume()` is equivalent to calling `perf_buffer__poll()` with a timeout of zero.

#### Asynchronous callbacks

On Linux perf buffers support only synchronous callbacks (using poll/consume).
Windows eBPF now supports both synchronous callbacks (default, matching Linux) and asynchronous perf buffer callbacks.

For synchronous callbacks (Linux-compatible), use the default behavior with `perf_buffer__new()`.
For asynchronous callbacks (Windows-specific), use `ebpf_perf_buffer__new()` with the `EBPF_PERFBUF_FLAG_AUTO_CALLBACK` flag.

#### Memory mapped consumers

Linux perf buffer consumers can directly access the per-CPU ring buffer data by calling `mmap()` on a perf_buffer map fd.
`perf_buffer__epoll_fd()` is used on Linux to get an fd to use with epoll to wait for data.

**Windows does not support direct memory mapped access to perf event arrays** because the Windows perf event array implementation does not use the same memory layout as Linux. Instead, use the synchronous callback APIs with wait handles for similar functionality.

For waiting on perf buffer data on Windows, use `ebpf_perf_buffer_get_wait_handle()` to get a HANDLE
to use with `WaitForSingleObject`/`WaitForMultipleObject`.

## bpf helpers

```c
/**
 * @brief Write raw data blob into a special BPF perf event held by a map of type BPF_MAP_TYPE_PERF_EVENT_ARRAY.
 *
 * In addition to specifying the cpu in flags, bpf programs with a data pointer in their context can pass a non-zero
 * value in BPF_F_CTXLEN_MASK (shifted 32 bits left from the cpu id) to append that many bytes from the data pointer
 * to the passed data. The data + payload are placed in the same perf event array record.
 *
 * @param ctx The context of the program.
 * @param map The BPF map of type BPF_MAP_TYPE_PERF_EVENT_ARRAY.
 * @param flags Flags indicating the index in the map for which the value must be put, masked with BPF_F_INDEX_MASK.
 * Alternatively, flags can be set to BPF_F_CURRENT_CPU to indicate that the index of the current CPU core should be used.
 * Only supports writing to the current CPU (pass BPF_F_CURRENT_CPU or manually specify current CPU at dispatch).
 * @param data The value to write, passed through eBPF stack and pointed by data.
 * @param size The size of the value to write.
 *
 * @return 0 on success, or a negative error in case of failure.
 */
long bpf_perf_event_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)
```

## libbpf API

```c
struct perf_buffer;

// Callback definitions.
typedef void (*perf_buffer_sample_fn)(void *ctx, int cpu,
                                      void *data, __u32 size);
typedef void (*perf_buffer_lost_fn)(void *ctx, int cpu, __u64 cnt);

// Perf buffer manager options.
struct perf_buffer_opts {
    size_t sz;
};

/* Windows-specific extended options */
struct ebpf_perf_buffer_opts {
  size_t sz; /* size of this struct, for forward/backward compatibility */
  uint64_t flags; /* perf buffer option flags */
};

/* Perf buffer option flags (Windows-specific) */
/* The default behavior is now synchronous callbacks to match Linux libbpf */
enum ebpf_perf_buffer_flags {
  EBPF_PERFBUF_FLAG_AUTO_CALLBACK = (uint64_t)1 << 0, /* Automatically invoke callback for each record */
};

#define perf_buffer_opts__last_field sz
#define ebpf_perf_buffer_opts__last_field flags

/**
 * @brief **perf_buffer__new()** creates BPF perfbuffer manager for a specified
 *        BPF_PERF_EVENT_ARRAY map (Linux-compatible, synchronous)
 * 
 * @param map_fd FD of BPF_PERF_EVENT_ARRAY BPF map that will be used by BPF
 * code to send data over to user-space
 * @param page_cnt number of memory pages allocated for each per-CPU buffer. Should be set to 0.
 * @param sample_cb function called on each received data record
 * @param lost_cb function called when record loss has occurred
 * @param ctx user-provided extra context passed into *sample_cb* and *lost_cb*
 * @param opts perfbuffer manager options. Not supported currently. Should be null.
 * @return a new instance of struct perf_buffer on success, NULL on error.
 */
LIBBPF_API struct perf_buffer *
perf_buffer__new(int map_fd, size_t page_cnt,
                 perf_buffer_sample_fn sample_cb, perf_buffer_lost_fn lost_cb, void *ctx,
                 const struct perf_buffer_opts *opts);

/**
 * @brief Poll perfbuf for new data.
 *
 * @param[in] pb Pointer to perf buffer manager.
 * @param[in] timeout_ms Timeout in milliseconds. Use -1 for infinite, 0 for non-blocking.
 * @returns Number of records consumed, or negative error code.
 */
int perf_buffer__poll(struct perf_buffer *pb, int timeout_ms);

/**
 * @brief Consume available records without waiting.
 *
 * @param[in] pb Pointer to perf buffer manager.
 * @returns Number of records consumed, or negative error code.
 */
int perf_buffer__consume(struct perf_buffer *pb);

/**
 * @brief Consume records from a specific per-CPU buffer.
 *
 * @param[in] pb Pointer to perf buffer manager.
 * @param[in] buf_idx Index of the per-CPU buffer to consume from.
 * @returns Number of records consumed, or negative error code.
 */
int perf_buffer__consume_buffer(struct perf_buffer *pb, size_t buf_idx);

/**
 * @brief Get number of per-CPU buffers.
 *
 * @param[in] pb Pointer to perf buffer manager.
 * @returns Number of per-CPU buffers.
 */
size_t perf_buffer__buffer_cnt(struct perf_buffer *pb);

/**
 * @brief Frees a perf buffer manager.
 *
 * @param[in] pb Pointer to perf buffer manager to be freed.
 */
void perf_buffer__free(struct perf_buffer *pb);

/**
 * @brief Create a new perf buffer manager with Windows-specific options.
 *
 * @param[in] map_fd File descriptor of BPF_MAP_TYPE_PERF_EVENT_ARRAY map.
 * @param[in] page_cnt Number of memory pages allocated for each per-CPU buffer. Should be set to 0.
 * @param[in] sample_cb Function called on each received data record.
 * @param[in] lost_cb Function called when record loss has occurred.
 * @param[in] ctx User-provided context passed into sample_cb and lost_cb.
 * @param[in] opts Windows-specific perf buffer manager options.
 *
 * @returns Pointer to perf buffer manager on success, null on error.
 */
_Ret_maybenull_ struct perf_buffer*
ebpf_perf_buffer__new(
    int map_fd,
    size_t page_cnt,
    perf_buffer_sample_fn sample_cb,
    perf_buffer_lost_fn lost_cb,
    _In_opt_ void* ctx,
    _In_opt_ const struct ebpf_perf_buffer_opts* opts) EBPF_NO_EXCEPT;

/**
 * @brief Get the wait handle to use with WaitForSingleObject/WaitForMultipleObject.
 *
 * @param[in] pb Pointer to perf buffer manager.
 * @returns Wait handle, or ebpf_handle_invalid if not available.
 */
ebpf_handle_t ebpf_perf_buffer_get_wait_handle(struct perf_buffer *pb);
```

### Perf buffer consumer examples

#### Synchronous polling consumer (Linux-compatible)

```c
// sample callback
void perf_buffer_sample_fn(void *ctx, int cpu, void *data, size_t size) {
  // … business logic to handle record …
}

// lost callback
void perf_buffer_lost_fn(void *ctx, int cpu, uint64_t cnt) {
  // … handle lost records …
}

// consumer code
fd_t map_fd = bpf_obj_get(perf_map_name.c_str());
if (map_fd == ebpf_fd_invalid) return 1;

struct perf_buffer *pb = perf_buffer__new(map_fd, 0, perf_buffer_sample_fn, perf_buffer_lost_fn, nullptr, nullptr);
if (pb == NULL) return 1;

// now loop as long as there isn't an error
while(perf_buffer__poll(pb, -1) >= 0) {
  // data processed by event callback
}

perf_buffer__free(pb);
```

#### Per-CPU buffer consumer (linux-compatible)

```c
// Consumer code.
fd_t map_fd = bpf_obj_get(perf_map_name.c_str());
if (map_fd == ebpf_fd_invalid) return 1;

struct perf_buffer *pb = perf_buffer__new(map_fd, 0, perf_buffer_sample_fn, perf_buffer_lost_fn, nullptr, nullptr);
if (pb == NULL) return 1;

// Get the number of per-CPU buffers.
size_t buffer_count = perf_buffer__buffer_cnt(pb);

// Process records from specific CPU buffers.
for (size_t i = 0; i < buffer_count; i++) {
    int result = perf_buffer__consume_buffer(pb, i);
    if (result < 0) {
        // Error occurred processing this buffer.
        continue;
    }
    // Records from CPU i were processed by callback.
}

perf_buffer__free(pb);
```

#### Asynchronous perf buffer consumer (Windows-specific)

```c
// sample callback - this will be called automatically for each record
void perf_buffer_sample_fn(void *ctx, int cpu, void *data, size_t size) {
  // … business logic to handle record …
}

// lost callback - this will be called automatically when records are lost
void perf_buffer_lost_fn(void *ctx, int cpu, uint64_t cnt) {
  // … handle lost records …
}

// consumer code
fd_t map_fd = bpf_obj_get(perf_map_name.c_str());
if (map_fd == ebpf_fd_invalid) return 1;

// Set up Windows-specific perf buffer options for automatic callbacks
struct ebpf_perf_buffer_opts opts = {};
opts.sz = sizeof(opts);
opts.flags = EBPF_PERFBUF_FLAG_AUTO_CALLBACK; // Enable automatic callbacks

struct perf_buffer *pb = ebpf_perf_buffer__new(map_fd, 0, perf_buffer_sample_fn, perf_buffer_lost_fn, nullptr, &opts);
if (pb == NULL) return 1;

// With automatic callbacks, the callback functions are invoked immediately
// when each record is written to any per-CPU buffer. No polling is needed.

// Keep the application running while callbacks are processed
// (actual application logic would determine when to exit)
Sleep(60000); // Sleep for 60 seconds or until application should exit

perf_buffer__free(pb);
```

#### Wait handle consumer (Windows-specific)

```c
// consumer code
fd_t map_fd = bpf_obj_get(perf_map_name.c_str());
if (map_fd == ebpf_fd_invalid) return 1;

struct perf_buffer *pb = perf_buffer__new(map_fd, 0, perf_buffer_sample_fn, perf_buffer_lost_fn, nullptr, nullptr);
if (pb == NULL) return 1;

// Get wait handle for blocking on new data
ebpf_handle_t wait_handle = ebpf_perf_buffer_get_wait_handle(pb);
if (wait_handle == ebpf_handle_invalid) {
    perf_buffer__free(pb);
    return 1;
}

// Event processing loop
while (true) {
    // Wait for data to become available
    DWORD wait_result = WaitForSingleObject(reinterpret_cast<HANDLE>(wait_handle), INFINITE);

    if (wait_result == WAIT_OBJECT_0) {
        // Data is available, consume all available records
        int result = perf_buffer__consume(pb);
        if (result < 0) {
            // Error occurred
            break;
        }
    } else {
        // Wait failed or was abandoned
        break;
    }
}

perf_buffer__free(pb);
```

## API Differences and Unsupported Features

### Supported APIs
- `perf_buffer__new()` - Linux-compatible synchronous perf buffer manager
- `ebpf_perf_buffer__new()` - Windows-specific perf buffer manager with async/sync flags
- `perf_buffer__poll()` - Poll for new data with timeout
- `perf_buffer__consume()` - Consume available data without waiting
- `perf_buffer__consume_buffer()` - Consume records from specific per-CPU buffer
- `perf_buffer__buffer_cnt()` - Get number of per-CPU buffers
- `perf_buffer__free()` - Free perf buffer manager
- `ebpf_perf_buffer_get_wait_handle()` - Get wait handle for blocking (Windows-specific)

### Unsupported APIs
The following Linux libbpf perf buffer APIs are **not supported** in ebpf-for-windows:

- `perf_buffer__new_raw()` - Raw perf buffer creation with custom CPU selection
- `perf_buffer__new_deprecated()` - Deprecated perf buffer creation API
- `perf_buffer__buffer()` - Direct access to per-CPU buffer memory
- `perf_buffer__buffer_fd()` - Get file descriptor for specific CPU buffer
- `perf_buffer__epoll_fd()` - Get epoll file descriptor (Windows uses wait handles instead)

### Memory Layout Differences
Unlike Linux, **Windows does not expose direct memory-mapped access** to perf event array buffers:
1. Windows perf event arrays use a different internal memory layout than Linux.
2. Windows uses wait handles instead of epoll for event notification.
3. The per-CPU buffer implementation differs between platforms.

For direct memory access to rings, consider using ring buffer maps instead, which do support memory-mapped access.
