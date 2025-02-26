# eBPF Ring Buffer Map

ebpf-for-windows exposes the [libbpf.h](/include/bpf/libbpf.h) interface for user-mode code.

*More documentation on user-mode API to be added later.*

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

|<-------------ring memory------------->|<-----2nd mapping of ring memory------>|
|123456789-123456789-123456789-123456789|123456789-123456789-123456789-123456789|
                 ^            ^
>================|            |=========>...  <- producer owned (new records reserved here)
                 |============|               <- consumer readable portion
              consumer     producer
```

The memory for the ring is split into two portions by a producer offset and consumer offset and mapped twice sequentially in memory.

- The producers own the portion of the ring from the producer offset to the consumer offset (modulo the ring length).
- Double-mapping the memory automatically handles reading and writing records that wrap around.

### Ring buffer structure

```c
typedef struct _ebpf_ring_buffer
{
    size_t length;
    volatile size_t consumer_offset; ///< Consumer has read up to here.
    volatile size_t producer_offset; ///< Producer(s) have reserved records up to here.
    volatile size_t producer_reserve_offset; ///< Next record to be reserved.
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

- A dispatch-level producer interupting a passive producer between steps (6-8) would hang on step (5) since
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
    - Poll until consumer offset != producer offset to wait for next record.
4. Read the record header at the consumer offset.
    - Uses read-acquire to ensure that the record data is visible before we try to read it.
5. If the record header is locked, stop reading.
    - It is possible later records are ready, but the consumer must read records in-order.
    - Poll the lock bit of the current record to wait for the next record.
6. If the current record has been discarded, advance the consumer offset and goto step (3).
7. If the current record has not been discarded, read it.
    - Advance the consumer offset after reading the record and goto step (3) to keep reading.
8. WriteNoFence advance consumer offset to next record and goto step (1).
    - Add data length, header length (8 bytes), and pad to a multiple of 8 bytes.
