# Conformance Notes: Ring Buffer Model

This document maps the TLA+ model in `models/ring_buffer/RingBufferModel.tla` to the implementation.

## Source locations

Ring buffer map plumbing:
- `libs/execution_context/ebpf_maps.c`
  - `ebpf_ring_buffer_map_output()` (signals async query completion after output)
  - `_async_query_ring_buffer_map()` / `_map_async_query()`
  - `_map_async_query_complete()`
  - `_query_ring_buffer_map()`
  - `_query_buffer_ring_buffer_map()` / `_return_buffer_ring_buffer_map()`
  - `_map_user_ring_buffer_map()` / `_unmap_user_ring_buffer_map()`

Ring buffer core implementation:
- `libs/runtime/ebpf_ring_buffer.c`
  - `ebpf_ring_buffer_reserve()` / `ebpf_ring_buffer_reserve_exclusive()`
  - `ebpf_ring_buffer_submit()` / `ebpf_ring_buffer_discard()`
  - `_ring_next_consumer_record()` and `ebpf_ring_buffer_next_consumer_record()`
  - `ebpf_ring_buffer_return_buffer()`
  - `ebpf_ring_buffer_query()`

Record format / lock+discard bits:
- `libs/shared/ebpf_ring_buffer_record.h`

## Model-to-code mapping

### Offsets

Model variables:
- `consumer`: corresponds to the consumer offset (`consumer_page->consumer_offset`).
- `producer`: corresponds to the published producer offset (`producer_page->producer_offset`).
- `reserve`: corresponds to the producer reserve offset (`kernel_page->producer_reserve_offset`).

In the C code, the key safety ordering is:
- reserve initializes a record header with the lock bit set
- then write-releases the `producer_offset` so the consumer cannot observe an uninitialized/unlocked record header

The model captures this ordering via `ProducerReserve` vs `ProducerReserveBuggyPublish`.

### Record state machine

Model record `state`:
- `Locked`: reserved and not yet submitted/discarded (lock bit set)
- `Submitted`: submitted (lock bit cleared, discard bit clear)
- `Discarded`: discarded (lock bit cleared, discard bit set)
- `Uninit`: represents a not-yet-locked/initialized header (this should not become visible to the consumer in the safe model)

This corresponds to `header.length` (plus lock/discard bits) in `ebpf_ring_buffer_record_t`.

### Consumer behavior

Model actions:
- `ConsumerNext`: approximates `_ring_next_consumer_record()`:
  - returns NULL if the next record is locked
  - skips discarded records by advancing the consumer offset
  - otherwise "holds" the record for return
- `ConsumerReturn`: approximates `ebpf_ring_buffer_return_buffer()` for the normal, valid return case

The model intentionally does not explore invalid return offsets; it focuses on the producer/consumer ordering guarantees.

### Async query

Model actions:
- `AsyncQuery`: approximates `_map_async_query()` for ring-buffer maps
- `AsyncComplete`: approximates `_map_async_query_complete()`

The model reflects the key constraint in `ebpf_maps.c` that only one async query may be pending at a time.

## Configurations

- `RingBufferModel.cfg`:
  - `BuggyPublishBeforeLock = FALSE`
  - Expected: invariants hold.

- `RingBufferModel_buggy_publish_before_lock.cfg`:
  - `BuggyPublishBeforeLock = TRUE`
  - Expected: `Safety` is violated (consumer can "hold" an `Uninit` record).

## Known gaps

- No attempt to model the full multi-producer reserve loop / compare-exchange serialization.
- No modeling of wait handle signaling semantics (only the notion of async completion).
- No modeling of record size alignment/padding beyond abstract unit sizes.
