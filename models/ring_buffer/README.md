# Ring Buffer TLA+ Model

This folder contains a bounded TLA+ model of the ring buffer behaviors as they are exposed through the map plumbing in `libs/execution_context/ebpf_maps.c`.

## What this model covers

- Producer reserving space and publishing the producer offset.
- Producer submitting or discarding a record (unlocking it).
- Consumer reading the next record in-order, skipping discarded records.
- Consumer returning space by advancing the consumer offset.
- Map async query: a single pending query that completes when `producer > consumer`.

## Files

- `RingBufferModel.tla`: the model.
- `RingBufferModel.cfg`: "safe" configuration (expected to pass invariants).
- `RingBufferModel_buggy_publish_before_lock.cfg`: intentionally buggy configuration (expected to fail `Safety`).

## Safety property checked

The core invariant is `Safety`:

- The consumer must never "hold" (consume) a record unless it is in the `Submitted` state.

This is meant to capture the essential guarantee provided by the acquire/release ordering in the C implementation: the consumer should not observe an uninitialized record as consumable.

## Running TLC locally

From the repo root:

- Safe model (expected PASS):
  - `"C:\Program Files\Microsoft\jdk-21.0.9.10-hotspot\bin\java.exe" -cp models\tla2tools.jar tlc2.TLC -workers auto models\ring_buffer\RingBufferModel.tla -config models\ring_buffer\RingBufferModel.cfg`

- Buggy model (expected FAIL):
  - `"C:\Program Files\Microsoft\jdk-21.0.9.10-hotspot\bin\java.exe" -cp models\tla2tools.jar tlc2.TLC -workers auto models\ring_buffer\RingBufferModel.tla -config models\ring_buffer\RingBufferModel_buggy_publish_before_lock.cfg`

If Java is already on your `PATH`, you can replace the quoted `java.exe` path with `java`.

## Notes / limitations

- The model uses an abstract unit size and does not represent actual bytes, alignment, `page_offset`, or the mmap header pages.
- It models a single consumer and does not model the full multi-producer reserve loop.
- It is a bounded model: `Capacity`, `MaxOffset`, and `MaxLiveRecords` limit the state space for TLC.
