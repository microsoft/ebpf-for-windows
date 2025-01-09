# Perf Event Array

This document proposes support for a simplified version of the linux bpf map type BPF_MAP_TYPE_PERF_EVENT_ARRAY.

# Background

On linux there are two map types for sending large amounts of data from BPF programs to user space.

The older one is the perf event array, which on linux interfaces with the linux perf subsystem to provide
per-cpu ring buffers. The perf subsystem has many other features (including counters and hardware event support)
and some of them are exposed via bpf.

The newer option is the ring buffer map, which is a single ring buffer (not per-cpu).

There are 3 primary differences between ring buffer maps and perf event arrays:
  - We are just looking at transfering variable sized records between kernel and user space (not other linux perf features)
  1. Perf event arrays are per-cpu, whereas ring buffers are a single shared buffer
  2. Ring buffer maps support reserve and submit to separately allocate and then fill in the record
  3. For specific program types with a payload, perf event arrays can copy payload from the bpf context by
  putting the length to copy in the `BPF_F_CTXLEN_MASK` field of the flags
      - `perf_event_output` takes the bpf context as an argument and the helper implementation copies the payload

The main motivation for this proposal is to efficiently support payload capture from the context in bpf programs.
- Supporting ring buffer reserve and submit in ebpf-for-windows is blocked on verifier support [#273](https://github.com/vbpf/ebpf-verifier/issues/273)
- without reserve+submit, using `ringbuf_output` for payload capture requires using a per-cpu array as scratch space to append the payload to the event before calling ringbuf_output
- the CTXLEN field in the flags of `perf_event_output` tells the kernel to append bytes from the payload to the record, avoiding the extra copy


# Proposal

The proposed behaviour matches linux, but currently only supports user-space consumers and bpf-program producers with a subset of the features.

The plan is to implement perf buffers using the existing per-cpu and ring buffer maps support in ebpf-for-windows.

1. Implement a new map type `BPF_MAP_TYPE_PERF_EVENT_ARRAY`.
    1. Initially only support bpf programs as producers and user space as consumer
    2. The behaviour will match linux perf event arrays, but only support a subset of the features
    3. For now no watermark support or other linux perf features, just output and poll
2. Implement `perf_event_output` bpf helper function
    1. Support BPF_F_INDEX_MASK, BPF_F_CURRENT_CPU, BPF_F_CTXLEN_MASK flags
2. Implement libbpf support for perf event arrays.
    1. `perf_buffer__new` - create a new perfbuf manager (and attach callback to map)
    2. `perf_buffer__free` - 
    3. `perf_buffer__poll` - wait the buffer to be non-empty (or timeout), then invoke callback for each ready record
        1. Callbacks will only be done synchronously in calls to `poll` (to match linux behaviour)

## bpf helpers
```c
 * long bpf_perf_event_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)
 * 	Description
 * 		Write raw *data* blob into a special BPF perf event held by
 * 		*map* of type **BPF_MAP_TYPE_PERF_EVENT_ARRAY**. This perf
 * 		event must have the following attributes: **PERF_SAMPLE_RAW**
 * 		as **sample_type**, **PERF_TYPE_SOFTWARE** as **type**, and
 * 		**PERF_COUNT_SW_BPF_OUTPUT** as **config**.
 *
 * 		The *flags* are used to indicate the index in *map* for which
 * 		the value must be put, masked with **BPF_F_INDEX_MASK**.
 * 		Alternatively, *flags* can be set to **BPF_F_CURRENT_CPU**
 * 		to indicate that the index of the current CPU core should be
 * 		used.
 *
 * 		The value to write, of *size*, is passed through eBPF stack and
 * 		pointed by *data*.
 *
 * 		The context of the program *ctx* needs also be passed to the
 * 		helper.
 *
 * 		On user space, a program willing to read the values needs to
 * 		call **perf_event_open**\ () on the perf event (either for
 * 		one or for all CPUs) and to store the file descriptor into the
 * 		*map*. This must be done before the eBPF program can send data
 * 		into it. An example is available in file
 * 		*samples/bpf/trace_output_user.c* in the Linux kernel source
 * 		tree (the eBPF program counterpart is in
 * 		*samples/bpf/trace_output_kern.c*).
 *
 * 		**bpf_perf_event_output**\ () achieves better performance
 * 		than **bpf_trace_printk**\ () for sharing data with user
 * 		space, and is much better suitable for streaming data from eBPF
 * 		programs.
 *
 * 		Note that this helper is not restricted to tracing use cases
 * 		and can be used with programs attached to TC or XDP as well,
 * 		where it allows for passing data to user space listeners. Data
 * 		can be:
 *
 * 		* Only custom structs,
 * 		* Only the packet payload, or
 * 		* A combination of both.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
```

## libbpf API
```c
struct perf_buffer;

typedef void (*perf_buffer_sample_fn)(void *ctx, int cpu,
				      void *data, __u32 size);
typedef void (*perf_buffer_lost_fn)(void *ctx, int cpu, __u64 cnt);

struct perf_buffer_opts {
	size_t sz;
};
#define perf_buffer_opts__last_field sz

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
