# Perf Event Array

This document describes the in-progress support for the bpf map type BPF_MAP_TYPE_PERF_EVENT_ARRAY ([#658](https://github.com/microsoft/ebpf-for-windows/issues/658)).

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

The main motivation for this proposal is to efficiently support payload capture from the context in bpf programs.
- Supporting ring buffer reserve and submit in ebpf-for-windows is currently blocked on verifier support [#273](https://github.com/vbpf/ebpf-verifier/issues/273).
- Without reserve+submit, using `ringbuf_output` for payload capture requires using a per-CPU array as scratch space to append the payload to the event before calling ringbuf_output.
- The CTXLEN field in the flags of `perf_event_output` tells the kernel to append bytes from the payload to the record, avoiding the extra copy.
  - On Linux this works for specific program types, on Windows this will work for any program type with a data pointer in the context.


## Proposal

The proposed behaviour matches Linux, but currently only supports user-space consumers and bpf-program producers with a subset of the features.

The plan is to implement perf buffers using the existing per-CPU and ring buffer map support in ebpf-for-windows.

To match Linux behaviour, by default the callback will only be called inside calls to `perf_buffer__poll()`.
If the PERFBUF_FLAG_AUTO_CALLBACK flag is set, the callback will be automatically invoked when there is data available.

1. Implement a new map type `BPF_MAP_TYPE_PERF_EVENT_ARRAY`.
    1. Linux-compatible default behaviour.
        - With Linux-compatible behaviour and bpf interfaces, additional features from Linux should be possible to add in the future.
    2. Only support the perf ringbuffer (not other Linux perf features).
        - Only support bpf program producers with a single user-space consumer per event array.
        - Features not supported include perf counters, hardware-generated perf events,
          attaching bpf programs to perf events, and sending events from user-space to bpf programs.
    3. In addition to the Linux behaviour, automatically invoke the callback if the auto callback flag is set.
2. Implement `perf_event_output` bpf helper function.
    1. Only support writing to the current CPU (matches current Linux restrictions).
        - Specify current CPU in flags using BPF_F_INDEX_MASK or pass BPF_F_CURRENT_CPU.
    2. Support BPF_F_CTXLEN_MASK flags for any bpf program types with a data pointer in the context.
        - The global helper will copy the memory from the program-type specific context data pointer,
          so no extension-specific helpers will be needed.
          - The extension-provided ebpf_context_descriptor_t includes the offset of the data pointer.
        - Passing a non-zero value in BPF_F_CTXLEN_MASK will return an operation not supported error for program types
          without a data pointer in the context.
2. Implement libbpf support for perf event arrays.
    1. `perf_buffer__new` - Create a new perfbuf manager (attaches callback).
        - Attaches to all CPUs automatically.
    2. `perf_buffer__new_raw` - Not supported initially (can be future work).
        - This function gives extra control over the perfbuf manager creation (e.g. which CPUs to attach).
    2. `perf_buffer__free` - Free perfbuf manager (detaches callback).
    3. `perf_buffer__poll` - Wait the buffer to be non-empty (or timeout), then invoke callback for each ready record.
        - By default (without `PERFBUF_FLAG_AUTO_CALLBACK`), the callback will not be called except inside poll() calls.
        - poll() should not be called if the auto callback flag is set.

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
    uint64_t flags;
};
#define perf_buffer_opts__last_field flags

// Flags for configuring perf buffer manager.
enum perf_buffer_flags {
    PERFBUF_FLAG_AUTO_CALLBACK = (uint64_t)1 << 0 /* Automatically invoke callback for each record */
};

/**
 * @brief **perf_buffer__new()** creates BPF perfbuf manager for a specified
 * BPF_PERF_EVENT_ARRAY map
 * @param map_fd FD of BPF_PERF_EVENT_ARRAY BPF map that will be used by BPF
 * code to send data over to user-space
 * @param page_cnt number of memory pages allocated for each per-CPU buffer
 * @param sample_cb function called on each received data record
 * @param lost_cb function called when record loss has occurred
 * @param ctx user-provided extra context passed into *sample_cb* and *lost_cb*
 * @return a new instance of struct perf_buffer on success, NULL on error with
 * *errno* containing an error code
 */
LIBBPF_API struct perf_buffer *
perf_buffer__new(int map_fd, size_t page_cnt,
		 perf_buffer_sample_fn sample_cb, perf_buffer_lost_fn lost_cb, void *ctx,
		 const struct perf_buffer_opts *opts);

/**
 * @brief poll perfbuf for new data
 * Poll for available data and consume records, if any are available.
 *
 * Must be called to receive callbacks by default (without auto callbacks).
 * NOT supported when PERFBUF_FLAG_AUTO_CALLBACK is set.
 *
 * If timeout_ms is zero, poll will not wait but only invoke the callback on records that are ready.
 * If timeout_ms is -1, poll will wait until data is ready (no timeout).
 *
 * @param[in] pb Pointer to perf buffer manager.
 * @param[in] timeout_ms maximum time to wait for (in milliseconds).
 *
 * @returns number of records consumed, INT_MAX, or a negative number on error
 */
int perf_buffer__poll(struct perf_buffer *pb, int timeout_ms);
/**
 * @brief Frees a perf buffer manager.
 *
 * @param[in] rb Pointer to perf buffer manager to be freed.
 */
void perf_buffer__free(struct perf_buffer *pb);
```
