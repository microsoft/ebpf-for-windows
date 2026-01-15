# Conformance notes: `HashTableModel.tla` vs `ebpf_hash_table.*`

This document explains what `models/hash_table/HashTableModel.tla` is modeling from:

- `libs/runtime/ebpf_hash_table.h`
- `libs/runtime/ebpf_hash_table.c`

and what it is intentionally simplifying.

## What the model is capturing

### Immutable buckets + pointer swap

In `ebpf_hash_table.c`, writers build a replacement bucket and publish it with release semantics:

- acquire read of current bucket pointer: `_ebpf_hash_table_get_bucket()`
- release write of new bucket pointer: `_ebpf_hash_table_set_bucket()`
- replacement operation under per-bucket lock: `_ebpf_hash_table_replace_bucket()`

In the model:

- `bucket_ptr[b]` corresponds to the published bucket pointer for bucket `b`.
- `bucket_contents[bo]` is the immutable map “inside” a bucket object `bo`.
- `WriterUpsert` / `WriterDelete` create a fresh bucket object and atomically update `bucket_ptr`.
- `ReaderBeginFind` snapshots `bucket_ptr[b]` into `snapshot_bucket[c]`, then `ReaderFinishFind` reads the entry from that snapshot.

### Epoch-based reclamation (simplified)

The C implementation uses epoch-based reclamation by default (`ebpf_epoch_allocate_with_tag` / `ebpf_epoch_free`), and relies on:

- publishing an epoch (global)
- recording active reader epochs
- advancing a released epoch
- reclaiming retired allocations only once it is safe

In the model:

- `published_epoch`, `released_epoch`, `cpu_epoch[c]` are a simplified epoch mechanism.
- buckets and value objects are “retired” on update/delete and later reclaimed by `ReclaimOne`.

## Safety property being checked

The invariant `Safety` checks:

- if `cpu_epoch[c] != 0` (reader is inside an epoch), then anything it holds/dereferences (`held_bucket`, `held_obj`) must not be in state `"Freed"`.

This corresponds to the intent that callers run hash-table reads under epoch protection so that `ebpf_epoch_free()` cannot reclaim memory out from under an active reader.

## Intentional simplifications

- No allocation failure paths (`EBPF_NO_MEMORY`), no notification callbacks, and no `supplemental_value_size` behavior.
- No modeling of `backup_bucket` reuse; deletes/updates are represented as “allocate new bucket object”.
- Not a full behavioral model of `ebpf_hash_table_iterate` / `*_next_key_*` APIs.
- Bucket hashing is abstracted by the constant function `BucketOf`.
- Writers are modeled as a single atomic action per operation; the real implementation uses an explicit per-bucket lock plus acquire/release pointer operations.

## Key assumptions to keep in sync

If the implementation changes, these are the assumptions the model is relying on:

- Buckets are immutable after publication (readers never see in-place bucket mutation).
- Publication is via a single pointer write with release semantics and read via acquire semantics.
- Retired buckets and values are reclaimed through epoch-based mechanisms (or something with equivalent safety).
- Read-side callers are expected to be under epoch protection for the lifetime of any returned pointer.
