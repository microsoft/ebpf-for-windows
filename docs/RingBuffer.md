# eBPF Ring Buffer Map

ebpf-for-windows exposes the [libbpf.h](/include/bpf/libbpf.h) interface for user-mode code.

*More documentation on user-mode API to be added later.*

## Synchronous Consumer Support (proposal)

The current ring buffer uses automatically invoked callbacks to read the ring buffer.
In contrast linux only supports synchronous ring buffer consumers using either the libbpf interface or directly
accessing the shared memory, with a wait handle to block and wait for new data.

This proposal adds support for synchronous callbacks (like libbpf on linux) and direct mapped memory access while preserving asynchronous callback support.

Asynchronous callback consumer:

1. Call `ring_buffer__new` to set up callback with RINGBUF_FLAG_AUTO_CALLBACK specified.
    - On Linux synchronous callbacks are always used, so the new AUTO_CALLBACK flags are Windows-specific.
    - Note: automatic callbacks are the current default behavior, but eventually
      this will change with [#4142](https://github.com/microsoft/ebpf-for-windows/issues/4142) to match the linux behavior so should always be specified.
2. The callback will be invoked for each record written to the ring buffer.

Synchronous callback consumer:

1. Call `ring_buffer__new` to set up callback with RINGBUF_FLAG_NO_AUTO_CALLBACK specified.
2. Call `ring_buffer__poll()` to wait for data if needed and invoke the callback on all available records.

Mapped memory consumer:

1. Call `ebpf_ring_buffer_map_map_buffer` to get pointers to the mapped producer/consumer pages.
2. Call `ebpf_map_set_wait_handle` to set the wait handle.
3. Directly read records from the producer pages (and update consumer offset as we read).
    - Use acquire and release semantics as described below for accessing record headers and ring offsets.
4. Call `WaitForSingleObject`/`WaitForMultipleObject` as needed to wait for new data to be available.

### Differences from linux API

#### Poll and Consume

On linux `ring_buffer__poll()` and `ring_buffer__consume()` are used to invoke the callback.
`poll()` waits for available data (or until timeout), then consume all available records.
`consume()` consumes all available records (without waiting).

Windows will initially only support `ring_buffer__poll()`, which can be called with a timeout of zero
to get the same behaviour as `ring_buffer__consume()`.

#### Asynchronous callbacks

On Linux ring buffers currently support only synchronous callbacks (using poll/consume).
In contrast, Windows eBPF currently supports only asynchronous ring buffer callbacks,
where the callback is automatically invoked when data is available.

This proposal adds support for synchronous consumers by setting the `RINGBUF_FLAG_NO_AUTO_CALLBACK` flag.
With the flag set, callbacks will not automatically be called.
To invoke the callback and `ring_buffer__poll()`
should be called to poll for available data and invoke the callback.
On Windows a timeout of zero can be passed to `ring_buffer__poll()` to get the same behaviour as `ring_buffer__consume()` (consume available records without waiting).

When #4142 is resolved the default behaviour will be changed from asynchronous (automatic) to synchronous callbacks,
so `RINGBUF_FLAG_AUTO_CALLBACK` should always be specified for asynchronous callbacks for forward-compatibility.

#### Memory mapped consumers

As an alternative to callbacks, Linux ring buffer consumers can directly access the
ring buffer data by calling `mmap()` on a ring_buffer map fd to map the data into user space.
`ring_buffer__epoll_fd()` is used on Linux to get an fd to use with epoll to wait for data.

Windows doesn't have directly compatible APIs to Linux mmap and epoll, so instead we will perfom the mapping
in the eBPF core and use a KEVENT to signal for new data.

For direct memory mapped consumers on Windows, use `ebpf_ring_buffer_get_buffer` to get pointers to the producer and consumer
pages mapped into user space, and `ebpf_ring_buffer_get_wait_handle()` to get the SynchronizationEvent (auto-reset) KEVENT
to use with `WaitForSingleObject`/`WaitForMultipleObject`.

Similar to the linux memory layout, the first pages of the shared ring buffer memory are the "producer page" and "consumer page",
which contain the 64 bit producer and consumer offsets as the first 8 bytes.
Only the producer may update the producer offset (read-only mapped into user-space)
and only the consumer should update the consumer offset.

### ebpf-for-windows API Changes

#### Changes to ebpf helper functions

```c
/**
 * @brief Output record to ringbuf
 *
 * Note newly added flag values (to specify wakeup options).
 *
 * Wakeup options (flags):
 * - 0 (auto/default): Notify if consumer has caught up.
 * - BPF_RB_FORCE_WAKEUP: Always notify consumer.
 * - BPF_RB_NO_WAKEUP: Never notify consumer.
 *
 */
ebpf_result_t
ebpf_ring_buffer_output(_Inout_ ebpf_ring_buffer_t* ring, _In_reads_bytes_(length) uint8_t* data, size_t length, size_t flags)
```

_Note:_ The currently internal `ebpf_ring_buffer_record.h` with helpers for working with raw records will also be made public.

#### Updated libbpf API for callback consumer

The default behaviour of these functions will be unchanged for now.

Use the existing `ring_buffer__new()` to set up automatic callbacks for each record.
Call `ebpf_ring_buffer_get_buffer()` ([New eBPF APIs](#new-ebpf-apis-for-mapped-memory-consumer))
to get direct access to the mapped ring buffer memory.

```c
struct ring_buffer;

typedef int (*ring_buffer_sample_fn)(_Inout_ void *ctx, _In_reads_bytes_(size) void *data, size_t size);

struct ring_buffer_opts {
  size_t sz; /* size of this struct, for forward/backward compatiblity */
  uint64_t flags; /* ring buffer option flags */
};

// Ring buffer manager options.
// - The default behaviour is currently automatic callbacks, but may change in the future per #4142.
// - Only specify one of AUTO_CALLBACKS or NO_AUTO_CALLBACKS - specifying both is not allowed.
enum ring_buffer_flags {
  RINGBUF_FLAG_AUTO_CALLBACK = (uint64_t)1 << 0 /* Automatically invoke callback for each record */
  RINGBUF_FLAG_NO_AUTO_CALLBACK = (uint64_t)2 << 0 /* Don't automatically invoke callback for each record */
};

#define ring_buffer_opts__last_field sz

/**
 * @brief Creates a new ring buffer manager.
 *
 * Only one consumer can be attached at a time, so it should not be called multiple times on an fd.
 *
 * If the return value is NULL the error will be returned in errno.
 *
 * @param[in] map_fd File descriptor to ring buffer map.
 * @param[in] sample_cb Pointer to ring buffer notification callback function (if used).
 * @param[in] ctx Pointer to sample_cb callback function context.
 * @param[in] opts Ring buffer options.
 *
 * @returns Pointer to ring buffer manager.
 */
struct ring_buffer *
ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, _Inout_ void *ctx,
		 _In_ const struct ring_buffer_opts *opts);

/**
 * @brief poll ringbuf for new data
 * Poll for available data and consume records, if any are available.
 *
 * If timeout_ms is zero, poll will not wait but only invoke the callback on records that are ready.
 * If timeout_ms is -1, poll will wait until data is ready (no timeout).
 *
 * This function is only supported when automatic callbacks are disabled (see RINGBUF_FLAG_NO_AUTO_CALLBACK).
 *
 * @param[in] rb Pointer to ring buffer manager.
 * @param[in] timeout_ms Maximum time to wait for (in milliseconds).
 *
 * @returns Number of records consumed, INT_MAX, or a negative number on error
 */
int ring_buffer__poll(_In_ struct ring_buffer *rb, int timeout_ms);

/**
 * @brief Frees a ring buffer manager.
 *
 * @param[in] rb Pointer to ring buffer manager to be freed.
 */
void ring_buffer__free(_Frees_ptr_opt_ struct ring_buffer *rb);
```

### New ebpf APIs for mapped memory consumer

```c
/**
 * Get the wait handle to use with WaitForSingleObject/WaitForMultipleObject.
 *
 * Get's the wait handle maintained by the ring buffer manager.
 *
 * Multiple calls will return the same handle, the ring buffer manager will close the handle when destroyed.
 *
 * @param[in] map_fd File descriptor to ring buffer map.
 *
 * @returns Wait handle
 */
ebpf_handle ebpf_ring_buffer_get_wait_handle(_In_ struct ring_buffer *rb);

/**
 * @brief Ring buffer consumer page definition.
 *
 * Definition of the consumer-writeable portion of the ring buffer metadata.
 * This page is read+write for the consumer and the producer only reads it.
 * An entire page is allocated for the consumer data but only the fields defined here should be
 * directly read/written (currently only the consumer offset).
 */
typedef struct _ebpf_ring_buffer_consumer_page
{
    volatile uint64_t consumer_offset; ///< Consumer has read up to this offset.
} ebpf_ring_buffer_consumer_page_t;

/**
 * @brief Ring buffer producer page definition.
 *
 * Definition of the producer-writeable portion of the ring buffer metadata.
 * This page is read+write for the producer and read-only for the consumer.
 * An entire page is allocated for the producer data but only the fields defined here should be directly accessed
 * (currently only the producer offset).
 *
 * This definition is for internal and consumer use; producers (eBPF programs) use helper functions to write new records.
 */
typedef struct _ebpf_ring_buffer_producer_page
{
    volatile uint64_t producer_offset; ///< Producer(s) have reserved up to this offset.
} ebpf_ring_buffer_producer_page_t;

/**
 * Get pointers to the consumer, producer, and data regions for the mapped ring buffer memory.
 *
 * Multiple calls will return the same pointers, as the ring buffer manager only maps the ring once.
 *
 * @param[in] rb Pointer to ring buffer manager.
 * @param[out] producer_page Pointer to start of read-only mapped producer page.
 * @param[out] consumer_page Pointer to start of read-write mapped consumer page.
 * @param[out] data Pointer to start of read-only double-mapped data pages.
 * @param[out] data_size Size of the mapped data buffer.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval other An error occurred.
 */
ebpf_result_t ebpf_ring_buffer_get_buffer(
    _In_ struct ring_buffer *rb,
    _Out_ ebpf_ring_buffer_consumer_page_t **consumer_page,
    _Out_ const ebpf_ring_buffer_producer_page_t **producer_page,
    _Outptr_result_buffer_(*data_size) const uint8_t **data,
    _Out_ uint64_t *data_size);

/**
 * Map ring buffer memory into user space and get pointers to the consumer, producer, and data regions.
 *
 * Calling this multiple times will map the ring into user-space multiple times.
 *
 * Note: This is a wrapper around ebpf_ring_buffer_map_map_user.
 *
 * @param[in] map_fd File descriptor to ring buffer map.
 * @param[out] producer_page Pointer to start of read-only mapped producer page.
 * @param[out] consumer_page Pointer to start of read-write mapped consumer page.
 * @param[out] data_size Size of the mapped data buffer.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval other An error occurred.
 */
ebpf_result_t ebpf_ring_buffer_map_map_buffer(
    fd_t map_fd,
    _Out_ ebpf_ring_buffer_consumer_page_t **consumer_page,
    _Out_ const ebpf_ring_buffer_producer_page_t **producer_page,
    _Outptr_result_buffer_(*data_size) const uint8_t **data,
    _Out_ const uint64_t *data_size);

/**
 * Map eBPF map memory into user space.
 *
 * Calling this multiple times will map the memory into user-space multiple times.
 *
 * For ring buffer maps the index must be zero.
 *
 * @param[in] map_fd File descriptor to map.
 * @param[in] index Map-specific index to map.
 * @param[out] data Pointer to start of mapped memory range.
 * @param[out] size Size of the mapped data buffer.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval other An error occurred.
 */
ebpf_result_t ebpf_ring_buffer_map_map_user(
    fd_t map_fd,
    uint64_t index,
    _Outptr_result_buffer_(*size) const uint8_t **data,
    _Out_ const uint64_t *size);

/**
 * Set the wait handle that will be signaled for new data.
 *
 * For ring buffer maps the index must be zero.
 *
 * @note Overwrites the wait handle currently stored in the map.
 *
 * @param[in] map_fd File descriptor to ring buffer map.
 * @param[in] index Map-specific index of wait handle to set.
 * @param[in] handle Wait handle to signal events on.
 *
 * @returns Wait handle
 */
ebpf_result_t ebpf_map_set_wait_handle(fd_t map_fd, uint64_t index, HANDLE handle);
```

### Ring buffer consumer

#### Mapped memory consumer example

This consumer directly accesses the records from the producer memory and directly updates the consumer offset to show the logic. Normally user code should use the ring buffer helpers
(see second example below) to simplify the logic.

```c++

//
// == Direct mapped memory consumer ==
//

// Open ring buffer.
fd_t map_fd = bpf_obj_get(rb_map_name.c_str());
if (map_fd == ebpf_fd_invalid) return 1;

// Create wait handle.
HANDLE wait_handle = CreateEvent(nullptr, false, false, nullptr);
if (wait_handle == NULL) {
    // … log error …
    goto Exit;
}

// Set map wait handle.
ebpf_result result = ebpf_map_set_wait_handle(map_fd, 0, wait_handle);
if (result != EBPF_SUCCESS) {
const volatile uint64_t *prod_offset = &rb_prod->producer_offset; // Producer offset ptr (read only).
    goto Exit;
}

ebpf_ring_buffer_consumer_page_t *rb_consumer_page; // Read/write consumer page.
const ebpf_ring_buffer_producer_page_t *rb_producer_page; // Read-only producer page.
const uint8_t* data; // Data region for records.

// Get pointers to the 3 regions.
result = ebpf_ring_buffer_map_map_buffer(map_fd, &rb_producer_page, &rb_consumer_page, &data);
if (result != EBPF_SUCCESS) {
    // … log error …
    goto Exit;
}

const volatile uint64_t *prod_offset = &rb_producer_page->producer_offset; // Producer offset ptr (read only).
volatile uint64_t *cons_offset = &rb_consumer_page->consumer_offset; // Consumer offset ptr (r/w mapped).

uint64_t producer_offset = ReadAcquire64(prod_offset);
uint64_t consumer_offset = ReadNoFence64(cons_offset);
// have_data used to track whether we should wait for notification or just keep reading.
bool have_data = producer_offset > consumer_offset;

// Now loop until error.
For(;;) {
  if (!have_data) { // Only wait if we have already caught up.
    // Wait for rb to notify -- or we could spin/poll until *prod_offset > *cons_offset.
    DWORD wait_status = WaitForSingleObject(wait_handle, INFINITE);

    if (wait_status != WAIT_OBJECT_0) { // No notification
      uint32_t wait_err = GetLastError();
      if (wait_err == /* terminal error */) {
        // … log error …
        break;
      }
      // It's possible we still have data, so check even though we got an error.
      producer_offset = ReadAcquire64(prod_offset);
      have_data = producer_offset > consumer_offset;
      if (!have_data) continue;
    } else { // We got notified of new data.
      have_data = true;
    }
  }
  uint64_t remaining = producer_offset - consumer_offset;

  // Check for empty ring.
  if (remaining == 0) {
    have_data = false; // Caught up to producer.
    continue;
  } else if (remaining < EBPF_RINGBUF_HEADER_SIZE) {
    // Bad record or consumer offset out of alignment.
    // … log error …
    break;
  }

  ebpf_ring_buffer_record_t *record = ebpf_ring_buffer_next_record(data, rb_size, consumer, producer);

  // Check if next record is locked.
  if (ebpf_ring_buffer_record_is_locked(record)) {
    have_data = false;
    continue;
    // Or we could spin/poll until ebpf_ring_buffer_record_is_locked(record) returns false.
  }

  if (!ebpf_ring_buffer_record_is_discarded(record)) {
    uint32_t record_length = ebpf_ring_buffer_record_length(record);
    // Read data from record->data[0 … record_length-1].
    // … business logic …
  } // Else it was discarded, skip and continue.

  // Update consumer offset.
  // Note: record_length is the data size, record_total_size includes header and padding.
  consumer_offset += ebpf_ring_buffer_record_total_size(record);
  WriteNoFence64(cons_offset,consumer_offset);
}

Exit:
```

#### Polling ring buffer consumer (using ringbuf manager)

```c
// sample callback
int ring_buffer_sample_fn(void *ctx, void *data, size_t size) {
  // … business logic to handle record …
}

// consumer code
struct ring_buffer_opts opts;
opts.sz = sizeof(opts);
opts.flags = RINGBUF_FLAG_NO_AUTO_CALLBACK; //no automatic callbacks

fd_t map_fd = bpf_obj_get(rb_map_name.c_str());
if (map_fd == ebpf_fd_invalid) return 1;

struct ring_buffer *rb = ring_buffer__new(map_fd, ring_buffer_sample_fn sample_cb, &opts);
if (rb == NULL) return 1;

// now loop as long as there isn't an error
while(ring_buffer__poll(rb, -1) >= 0) {
  // data processed by event callback
}

ring_buffer__free(rb);
```


### Linux consumer examples (for comparison)

#### Linux direct mmap consumer

```c
size_t page_size = 4096;

int map_fd = bpf_obj_get(rb_map_name.c_str());
if (map_fd < 0) return 1;

// Fetch map info to get max_entries
struct bpf_map_info info = {};
uint32_t info_len = sizeof(info);
if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) != 0) {
    // … handle error …
    close(map_fd);
    return 1;
}
size_t max_entries = info.max_entries;

int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
if (epoll_fd < 0) {
  // … handle error …
};

struct epoll_event event = {
  .events = EPOLLIN,
  .data.fd = map_fd
};

uint8_t* consumer = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);

size_t mmap_sz = page_size + 2 * max_entries;
const volatile uint8_t* producer = mmap(NULL, (size_t)mmap_sz, PROT_READ, MAP_SHARED, map_fd, page_size);
if (!producer || !consumer) {
  // … handle error …
};

if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, map_fd, &event) < 0) {
  // … handle error …
}

volatile uint64_t *cons_offset = (volatile uint64_t*)consumer;
const volatile uint64_t *prod_offset = (const volatile uint64_t*)consumer;
const volatile uint8_t *data = producer + page_size;

uint64_t producer_offset = ReadAcquire64(prod_offset);
uint64_t consumer_offset = ReadNoFence64(cons_offset);
// have_data used to track whether we should wait for notification or just keep reading.
bool have_data = producer_offset > consumer_offset;

// Now loop until error.
For(;;) {
  if (!have_data) { // Only wait if we have already caught up.
    struct epoll_event events[1];
    int nfds = epoll_wait(epoll_fd, events, 1, -1);
    if (nfds == 0) { // No signal
        continue;
    } else if (nfds < 0) {
      // … handle any terminal errors …
    }
    // It's possible we still have data, so check even if we got an error.
    producer_offset = ReadAcquire64(prod_offset);
    have_data = producer_offset > consumer_offset;
    if (!have_data) continue;
  }
  uint64_t remaining = producer_offset - consumer_offset;

  // Check for empty ring.
  if (remaining == 0) {
    have_data = false; // Caught up to producer.
    continue;
  } else if (remaining < 8) {
    // Bad record or consumer offset out of alignment.
    // … log error …
    break;
  }

  // Read the record header.
  const volatile uint8_t *record = data + (consumer_offset % (2 * page_size));
  uint32_t record_header = *(const volatile uint32_t *)record;
  uint32_t record_length = record_header & 0x3FFFFFFF; // Mask out lock/discard bits.

  // Check if the record is locked.
  if (record_header & (1U << 31)) {
      // Record is locked, wait for it to be unlocked
      continue;
  }

  // If not discarded handle the record.
  if (!(record_header & (1U << 30))) {
    const volatile uint8_t *record_data = record + 8;
    // Read data from record->data[0 … record_length-1].
    // … business logic …
  }


  // Update consumer offset.
  // Note: record_length is the data size, record_total_size includes header and padding.
  // Padding 8-byte aligns records.
  consumer_offset += ((record_length + 8) + 7) & ~7;
  WriteNoFence64(cons_offset,consumer_offset);
}

Exit:
close(epoll_fd);
munmap(consumer, page_size);
munmap(producer, mmap_sz);
close(map_fd);
```

#### Linux ring buffer manager consumer

```c
// sample callback
int ring_buffer_sample_fn(void *ctx, void *data, size_t size) {
  // … business logic to handle record …
}

fd_t map_fd = bpf_obj_get(rb_map_name.c_str());
if (map_fd == ebpf_fd_invalid) return 1;

struct ring_buffer *rb = ring_buffer__new(map_fd, ring_buffer_sample_fn sample_cb, NULL);
if (rb == NULL) return 1;

// now loop as long as there isn't an error
while(ring_buffer__poll(rb, -1) >= 0) {
  // data processed by event callback
}

ring_buffer__free(rb);
```

*Below implementation details of the internal ring buffer data structure are discussed.*

## Internal Ring Buffer

The ebpf-for-windows ring buffer map is built on the internal ring buffer implementation in
[ebpf_ring_buffer.h](/libs/runtime/ebpf_ring_buffer.h) and [ebpf_ring_buffer.c](/libs/runtime/ebpf_ring_buffer.c).

- These functions are internal to ebpf-for-windows. User mode code should use [libbpf.h](/include/bpf/libbpf.h).

This section describes the multiple-producer single-consumer internal ring buffer implementation.

- [Memory layout](#memory-layout) - Double-mapped ring with producer and consumer offset.
- [Ring buffer structure](#ring-buffer-structure) - Internal ring buffer struct.
- [Record structure](#record-structure) - Record structure.
- [Producer functions](#producer-functions) - Producer internal API functions.
- [Consumer functions](#consumer-functions) - Consumer internal API functions.
- [Synchronization](#synchronization) - Synchronization rules.
- [Producer aglorithm](#producer-algorithm) - multiple-producer reserve/submit algorithm for emitting records.
  - [Reserve algorithm](#reserve-algorithm)
  - [Submit and discard](#submit-and-discard)
- [Consumer algorithm](#consumer-algorithm) - consumer algorithm.

### Memory Layout

```text
|kernel page|consumer page|producer page|<-------------ring memory------------>|<----2nd mapping of ring memory------>|
                                                         ^            ^
                                        >================|            |========>... <-- free portion of ring
                                                         |============|             <-- unread and in-progress records
                                                      consumer     producer
                                                       offset       offset
```

The internal ring buffer has a header of 3 pages of memory followed by the data pages.
The data memory for the ring is split into two portions by a producer offset and consumer offset
and mapped twice sequentially in memory directly after the header pages.

- The kernel page is for internal use by producers.
- The consumer page has the consumer offset.
- The producer page has the producer offset.
- The producers own the portion of the ring from the producer offset to the consumer offset (modulo the ring length).
  - This is where new records are reserved. Newly reserved records are locked before the producer offset is updated.
- The consumer reads records in order starting at the consumer offset and stopping at the first locked record or on reaching the producer offset.
- Double-mapping the memory automatically handles reading and writing records that wrap around.

_Note:_ the 3-page header is not yet implemented - currently the ring buffer metadata is stored in a kernel data structure.
This will affect the structure layouts below when [#4163](https://github.com/microsoft/ebpf-for-windows/issues/4163)
is implemented, but has no impact on the below agorithm.


### Ring buffer structure

```c
typedef struct _ebpf_ring_buffer
{
    uint64_t length;
    volatile uint64_t consumer_offset; ///< Consumer has read up to here.
    volatile uint64_t producer_offset; ///< Producer(s) have reserved records up to here.
    volatile uint64_t producer_reserve_offset; ///< Next record to be reserved.
    uint8_t* shared_buffer;
    ebpf_ring_descriptor_t* ring_descriptor;
} ebpf_ring_buffer_t;
```

- Defined in [ebpf_ring_buffer.c](/libs/runtime/ebpf_ring_buffer.c)
- The producer and consumer offsets are used to synchronize between producers and the consumer.
- The producer reserve offset is used to serialize producer reservations.
- Offsets are modulo'd by the length to get the offset of a record in the shared buffer.

### Record structure

```c
#define EBPF_RINGBUF_LOCK_BIT (1U << 31)
#define EBPF_RINGBUF_DISCARD_BIT (1U << 30)
typedef struct _ebpf_ring_buffer_record
{
    // This struct should match the linux ring buffer record structure for future mmap compatibility (see #4163).
    struct
    {
        uint32_t length; ///< High 2 bits are lock,discard.
        uint32_t page_offset; ///< Currently unused.
    } header;
    uint8_t data[1];
} ebpf_ring_buffer_record_t;
```

- Defined in [ebpf_ring_buffer_record.h](/libs/shared/ebpf_ring_buffer_record.h).
- Record includes 8 byte header, with the first 4 bytes indicating the length and lock, discard flags.
  - `page_offset` is for future use with the submit and discard bpf helper functions.
  - 32-2 = 30 bit record length limits records to 1GB.
  - The lock and discard flags prevent the consumer from reading unfinished records.
  - *Note:* This matches the linux record structure for future ring buffer mmap-consumer compatibility (see [#4163](https://github.com/microsoft/ebpf-for-windows/issues/4163)).
- Records are padded to 8 byte alignment.
  - 64 bit alignment is required for acquire/release semantics on 64 bit architectures.
  - The consumer ignores and skips the padding (not included in the record length).

### Producer functions

Producers use reserve and submit to reserve space and submit completed records for reading.

- The algorithms are described below in [Producer algorithm](#producer-algorithm).
- `ebpf_ring_buffer_reserve` reserves a record and returns a pointer to the record data.
  - Returns `EBPF_NO_MEMORY` if there isn't enough space left for the record.
  - Wait-free with a single producer.
    - This is the only potentially blocking producer/consumer function (retry wait at dispatch).
- `ebpf_ring_buffer_submit` unlocks a record so that it can be read by the consumer
- `ebpf_ring_buffer_discard` marks record as discarded and unlocks it so the consumer can skip it.
- `ebpf_ring_buffer_output` calls reserve, copies the data into the record, then calls submit.
  - *Note:* due to verifier limitations reserve/submit helper functions aren't available (only output, see [#727](https://github.com/microsoft/ebpf-for-windows/issues/727).

### Consumer functions

The consumer can poll for new records to read using `ebpf_ring_buffer_next_consumer_record`,
and return the memory for reuse after reading by passing the returned `next_offset` to `ebpf_ring_buffer_return_buffer`.

- `ebpf_ring_buffer_next_consumer_record` also skips over any discarded records to return the memory to the ring.
- *Note:* Currently only the `ring_buffer_output` helper is available, so there are never discarded records.

A wait handle for producers to signal the consumer on is implemented at the eBPF map level,
while the internal ring buffer only handles the reading and writing of records.

### Synchronization

Specific memory ordering semantics are followed for record headers and the producer offset to
ensure synchronization between producers and the consumer.

- The consumer offset is only advanced by a single consumer, so doesn't have additional ordering constraints.
    - This is true if there is only a single consumer thread, but currently the reads are done in a thread pool,
      So the consumer uses read-acquire and write-release to ensure it always reads the latest value. This doesn't
      impact the algorithm presented here which assumes a single consumer thread.

1. Producers write-release the producer offset during reserve after locking the record.
    - Write-release ensures the locked record header is visible before the producer offset is updated.
2. Producers write-release the record header during submit/discard to unlock the record.
    - Write-release ensures the record data is visible before the record is unlocked.
    - This is also needed for discarded records to ensure any writes are completed before the space is reused.
3. Consumer read-acquires the producer offset to check for available records.
    - Read-acquire ensures all newly locked record headers are visible before we read them (with 1 above).
4. Consumer read-acquires record headers to check the lock bit.
    - Read-acquire ensures the record data is visible before we read it (with 2 above).

The above rules guarantee synchronization between producers and the consumer, ensuring records are initialized
before the consumer sees them and that the final record data is visible before the consumer reads or returns it.

To serialize reservations, producers use an interlocked compare-exchange on the `producer_reserve_offset`.

- Compare-exchange is used to atomically reserve space for the record after confirming there is space available.
- Producers busy-wait (at dispatch) for earlier concurrent reservations before advancing the next producer offset.
- See [Producer reserve](#producer-reserve) below for the full algorithm.

### Producer Algorithm

Implemented in [ebpf_ring_buffer.c](/libs/runtime/ebpf_ring_buffer.c).

Producers reserve a record, then copy the data, then submit the record.

- Note: the reserve/submit/discard eBPF program helpers aren't supported yet due to verifier limitations (see [#727](https://github.com/microsoft/ebpf-for-windows/issues/727)).
- The time between reserve and submit should be kept short to avoid blocking the consumer from reading later submitted records.

#### Reserve algorithm

1. Calculate the total record size with 8 byte header and padding to 8 byte alignment.
    - Aligned accesses must be used for acquire and release semantics.
2. Read the `consumer_offset`.
    - This can be no-fence because a stale value at worst means failing on a nearly full ring.
3. Read the `producer_reserve_offset`.
    - Uses read-acquire to ensure we see the latest value before compare-exchange (to reduce collisions/retries).
4. Confirm there is enough space for the record (or return failure).
    - Checking before compare-exchange ensures producers do not overrun the consumer.
5. Atomically advance the `producer_reserve_offset` to reserve space for the record using compare-exchange.
    - If the exchange suceeds, we now own the record space, continue to (6).
    - If the compare-exchange fails, another producer just allocated this space, goto (4) and try again.
      - Uses the updated `producer_reserve_offset` from the compare-exchange for the retry.
6. Write the locked record header to the ring.
    - This can be no-fence, the ordering of this write is enforced by (8) below.
7. Busy wait for the producer offset to match our reserved record offset.
    - Waits for any earlier in-progress reservations between steps (6-8) to update the producer offset.
      - Ensures producer offset is monotonically advanced.
    - At worst step we must wait for N-1 threads to get from step 6-8 for N cpus (reserve happens at dispatch).
    - Waiting for all previous producer offset updates also ensures all previous records have been initialized.
8. Update the producer offset.
    - Uses write-release to ensure the locked header written in (6) is visible no later than the producer offset update.

To prevent deadlock between passive and dispatch producers, steps (5-8) must be done at dispatch.

- A dispatch-level producer interupting a passive producer between steps (6-8) would hang on step (7) since
  the passive thread would never update the producer offset.

The reserve algorithm ensures reserves are serialized and the consumer never sees uninitialized records.

- The compare-exchange in (5) serializes reservations.
- The write-release in (8) ensures the locked record header is visible before the producer offset update.
- Waiting on the producer offset in (7) serializes producer offset updates (also ensuring previous headers are visible).

After the call to reserve, the producer can write to the record and then submit or discard.

The lock bit in the record header will be set when reserve returns, and will stay set until it is submitted or discarded.

#### Submit and discard

To submit or discard the record, the producer write-releases the header to ensure all writes to the record are visible.

- discard sets the discard bit in the header (as part of the write-release) to tell the consumer to skip this record.

### Consumer Algorithm

*Note:* Currently ebpf-for-windows only exposes the libbpf callback-based consumer API.

- This algorithm is used by the ring buffer map to check for new records when the wait handle is signaled.

1. Read consumer offset.
    - There is only a single consumer so can can use no-fence read here.
2. Read the producer offset.
    - Uses read-acquire to ensure the record header read below in (4) is read after the producer offset.
    - This read-acquire prevents the consumer from seeing records before they are initialized.
3. If consumer offset == producer offset the ring is empty.
    - Poll until consumer offset != producer offset (steps 2-3) to wait for next record.
4. Read the record header at the consumer offset.
    - Uses read-acquire to ensure that the record data is visible before we try to read it.
5. If the record header is locked, stop reading.
    - It is possible later records are ready, but the consumer must read records in-order.
    - Poll the lock bit of the current record (steps 4-5) to wait for the next record.
6. If the current record has been discarded, advance the consumer offset and goto step (3).
7. If the current record has not been discarded, read it.
    - Advance the consumer offset after reading the record and goto step (3) to keep reading.
8. WriteNoFence advance consumer offset to next record and continue from step (2).
    - Add data length, header length (8 bytes), and pad to a multiple of 8 bytes.
