# New ebpf Ring Buffer Map (proposal)

## Overview

The current ringbuffer uses a pure callback-based approach to reading the ringbuffer.
Linux also supports memory-mapped polling consumers, which can't be directly supported in the current model.

The new API will support 2 consumer types: callbacks and direct access to the mapped producer memory (with poll to wait for data).

Callback consumer:

1. Call `ring_buffer__new` to set up callback
2. Call `ring_buffer__consume` as needed to invoke the callback on any outsanding data that is ready

Mapped memory consumer:

1. Call `ring_buffer__new` to get a ringbuffer manager.
2. Call `ebpf_ring_buffer_get_buffer` to get pointers to the mapped producer/consumer pages.
3. Call `ebpf_ring_buffer_get_buffer` to get pointers to the mapped producer and consumer memory.
4. Call `ebpf_ring_buffer_get_wait_handle` to get the wait handle.
5. Directly read records from the producer pages (and update consumer offset as we read).
6. Call `WaitForSingleObject`/`WaitForMultipleObject` as needed to wait for new data to be available.

## API Changes

### Changes to ebpf helper functions

```c
/**
 * @brief Output record to ringbuf
 *
 * Note newly added flag values (to specify wakeup options).
 *
 * Wakeup options (flags):
 * - 0 (auto/default): Notify if consumer has caught up.
 * - BPF_RB_FORCE_WAKEUP - Always notify consumer.
 * - BPF_RB_NO_WAKEUP - Never notify consumer.
 *
 */
ebpf_result_t
ebpf_ring_buffer_output(ebpf_ring_buffer_t* ring, uint8_t* data, size_t length, size_t flags)
```

### Updated supported libbpf functions

```c

struct ring_buffer;

typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);

struct ring_buffer_opts {
	size_t sz; /* size of this struct, for forward/backward compatiblity */
};

#define ring_buffer_opts__last_field sz

/**
 * @brief Creates a new ring buffer manager.
 *
 * @param[in] map_fd File descriptor to ring buffer map.
 * @param[in] sample_cb Pointer to ring buffer notification callback function.
 * @param[in] ctx Pointer to sample_cb callback function context.
 * @param[in] opts Ring buffer options.
 *
 * @returns Pointer to ring buffer manager.
 */
struct ring_buffer *
ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx,
		 const struct ring_buffer_opts *opts);

/**
 * @brief Add extra RINGBUF maps to this ring buffer manager
 *
 * @param[in] rb Pointer to ring buffer manager.
 * @param[in] map_fd File descriptor to ring buffer map.
 * @param[in] sample_cb Pointer to ring buffer notification callback function.
 * @param[in] ctx Pointer to sample_cb callback function context.
 */
int ring_buffer__add(struct ring_buffer *rb, int map_fd,
		     ring_buffer_sample_fn sample_cb, void *ctx)

/**
 * @brief Frees a ring buffer manager.
 *
 * @param[in] rb Pointer to ring buffer manager to be freed.
 *
 */
void ring_buffer__free(struct ring_buffer *rb);

/**
 * @brief poll ringbuf for new data
 * Poll for available data and consume records, if any are available.
 * Returns number of records consumed (or INT_MAX, whichever is less), or
 * negative number, if any of the registered callbacks returned error.
 *
 * @param[in] rb Pointer to ring buffer manager.
 * @param[in] timeout_ms maximum time to wait for (in milliseconds).
 *
 */
int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms);

/**
 * @brief catch consumer up to producer by invoking the callback for every available record
 * Consume available ring buffer(s) data without event polling.
 * Returns number of records consumed across all registered ring buffers (or
 * INT_MAX, whichever is less), or negative number if any of the callbacks
 * return error.
 *
 * @param[in] rb Pointer to ring buffer manager.
 */
int ring_buffer__consume(struct ring_buffer *rb);
```

### New ebpf APIs

```c
/**
 * get pointers to mapped producer and consumer pages
 *
 * @param[out] producer pointer* to start of read-only mapped producer pages
 * @param[out] consumer pointer* to start of read-write mapped consumer page
 */
int ebpf_ring_buffer_get_buffer(const ebpf_map_t* map, void **producer, void **consumer);

/**
 * get the wait handle to use with WaitForSingleObject/WaitForMultipleObject
 *
 * @param[out] producer pointer* to start of read-only mapped producer pages
 * @param[out] consumer pointer* to start of read-write mapped consumer page
 *
 * @returns Wait handle
 */
HANDLE ebpf_ring_buffer_get_wait_handle(const ebpf_map_t* map);
```

## Ringbuffer consumer

### libbpf mapped memory consumer example


This consumer directly accesses the records from the producer memory and directly updates the consumer offset to show the logic.

```c++

//
// == Ringbuf helpers ==
//

// Ring buffer record is 64 bit header + data.
typedef struct _rb_header
{
    //NOTE: bit fields are not portable, so this is just for simpler example code -- the actual code should use bit masking to perform equivalent operations on the header bits.
    uint8_t locked : 1;
    uint8_t discarded : 1;
    uint32_t length : 30;
    uint32_t offset; // for kernel use (offset of record in pages from start of buffer data area)
} rb_header_t;

typedef struct _rb_record
{
    rb_header_t header;
    uint8_t data[];
} rb_record_t;

/**
 * @brief clear the ringbuffer.
 */
void rb_flush(uint64_t *cons_offset, const uint64_t *prod_offset) {
    *cons_offset = *prod_offset;
}


//
// == mmap/epoll consumer ==
//

void *rb_cons; // Pointer to read/write mapped consumer page with consumer offset.
void *rb_prod; // Pointer to start of read-only producer pages.

// Open ringbuffer.
fd_t map_fd = bpf_obj_get(rb_map_name.c_str());
if (map_fd == ebpf_fd_invalid) return 1;

auto rb = ring_buffer__new(
    map_fd,
    NULL, //callback function for callback-based consumer
    nullptr, nullptr);
if (!rb) return 1;

// Initialize iocp wait handle.
HANDLE wait_handle = ebpf_ring_buffer_get_wait_handle(rb);
if (!wait_handle) {
    // … log error …
    goto Cleanup;
}

// get pointers to the producer/consumer pages
int err = ebpf_ring_buffer_get_buffer(&rb_prod, &rb_cons);

if (err) {
    goto Cleanup;
}

const uint64_t *prod_offset = (const uint64_t*)rb_prod; // Producer offset ptr (r only).
uint64_t *cons_offset = (uint64_t*)rb_cons; // Consumer offset ptr (r/w mapped).
const uint8_t *rb_data = ((const uint8_t*)rb_prod) + PAGESIZE; // Double-mapped rb data ptr (r only).

// have_data used to track whether we should wait for notification or just keep reading.
bool have_data = *prod_offset > *cons_offset;

void           *lp_ctx = NULL;
OVERLAPPED     *overlapped = NULL;
DWORD          bytesTransferred = 0;

// Now loop until error.
For(;;) {
  if (!have_data) { // Only wait if we have already caught up.
    // Wait for rb to notify -- or we could spin/poll on *prod_offset > *cons_offset.
    DWORD wait_status = WaitForSingleObject(wait_handle, INFINITE);

    if (wait_status != WAIT_OBJECT_0) { // No notification
      uint32_t wait_err = GetLastError();
      if (wait_err == /* terminal error */) {
        // … log error …
        break;
      }
      have_data = *prod_offset > *cons_offset; // It's possible we still have data.
      if (!have_data) continue;
    } else { // We got notified of new data.
      have_data = true;
    }
  }
  uint64_t prod = *prod_offset;
  uint64_t cons = *cons_offset;
  uint64_t remaining = prod - cons;

  if (remaining == 0) {
    have_data = false; // Caught up to producer.
    continue;
  } else if (remaining < sizeof(rb_header_t)) {
    // Bad record or consumer offset out of alignment.
    // … log error …
    break;
  }

  // Check header flags first, then read/skip data and update offset.
  rb_header_t header = *(rb_header_t*)(&rb_data[cons % rb_size]);
  if (header.locked) { // Next record not ready yet, wait on iocp.
    have_data = false;
    continue;
    // Or we could spin/poll on ((rb_header_t*)(&rb_data[cons % rb_size]))->locked.
  }
  if (!header.discarded) {
    const rb_record_t *record = *(const rb_record_t*)(&rb_data[cons % rb_size]);
    // Read data from record->data[0 ... record->length-1].
    // … business logic …
  } // Else it was discarded, skip and continue.

  // Update consumer offset (and pad record length to multiple of 8).
  cons += sizeof(rb_header_t) + (record->length + 7 & ~7);
  *cons_offset = cons;
}

Cleanup:

// Close ringbuffer.
ring_buffer__free(rb);
```

### Simplified blocking ringbuf consumer

This consumer uses some possible helpers to simplify the above logic (might also want timeout).

```c
//Note: the below theoretical helpers would only need access to producers/consumer pages (offsets and data pages)
//rb__empty(prod,cons) - check whether consumer offset == consumer offset (!empty doesn't mean data is ready)
//rb__flush(prod,cons) - just set consumer offset = producer offset (skips all completed/in-progress records)
//rb__next_record(prod,cons) - advance consumer offset to next record
//rb__get_record(prod,cons,&record) - get pointer to current record (if any), skipping discarded records
//Returns E_SUCCESS (0) if record ready, E_LOCKED if record still locked, E_EMPTY if consumer has caught up.

for(;;) {
  for(; !(err=rb__get_record(prod,cons,&record)); rb__next_record(prod,cons)) {
    // Data is now in record->data[0 ... record->length-1].
    // … Do record handling here …
  }
  // 3 cases for err:
  // 1) Ringbuf empty - Wait with epoll, or poll for !rb__empty(prod,cons).
  // 2) Record locked - Wait with epoll, or spin/poll on header lock bit.
  // 3) Corrupt record or consumer offset - Break (could flush to continue reading from next good record).
  if (err!=E_EMPTY && err!=E_LOCKED) {
    // … log error …
    break;
  }
  if (err == /* Handled errors, e.g. timeout */) {
    // … log error and continue (we might still have record(s) to read) …
  } else if (err != E_SUCCESS) {
    // … log error …
    break;
  }
}
return err;
```
