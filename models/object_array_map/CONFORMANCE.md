# Conformance Notes: Object Array Map lock-free read model

This document maps `models/object_array_map/ObjectArrayMapModel.tla` to the relevant implementation patterns.

## Relevant implementation sites

Lock-free read of an object pointer from an array-map slot:
- `libs/execution_context/ebpf_maps.c`
  - `_find_object_array_map_entry()` uses `ReadULong64NoFence` to atomically load the object pointer without taking the map lock.
  - `_get_object_from_array_map_entry()` uses `ReadULong64NoFence` similarly.

Writer update under a lock:
- `libs/execution_context/ebpf_maps.c`
  - `_update_array_map_entry_with_handle()` runs under `object_map->lock`, releases the old object reference via `EBPF_OBJECT_RELEASE_REFERENCE(old_object)`, then writes the new pointer with `WriteULong64NoFence`.

Deferred destruction via epoch:
- `libs/runtime/ebpf_object.c`
  - `ebpf_object_release_reference()` schedules destruction using `ebpf_epoch_schedule_work_item(...)` when the reference count reaches zero.

## Model-to-code mapping

### Slot pointer

- Model variable `slot` represents the pointer-sized slot stored in `map->data[index * actual_value_size]`.
- Model action `ReaderLoad` represents the lock-free load via `ReadULong64NoFence`.

### Update and retirement

- Model action `WriterUpdate` represents the update under `object_map->lock`:
  - retiring the old object (conceptually after `EBPF_OBJECT_RELEASE_REFERENCE(old_object)`), and
  - writing the new pointer to the slot.

The model abstracts away reference counts and focuses on the lifetime effect:
- Objects are not actually freed immediately; they become `Retired` and are later `Freed` by `ReclaimOne`.

### Epoch rule / contract

- Model variables `publishedEpoch` and `readerEpoch` approximate the epoch guard described in the codebase.
- `AllowReadOutsideEpoch = FALSE` is the safe contract: the reader must be in an epoch before it loads the slot.
- `AllowReadOutsideEpoch = FALSE` is the safe contract: the reader must be in an epoch before it loads the slot and must drop/stop using the pointer before it exits the epoch.
- The buggy config sets `AllowReadOutsideEpoch = TRUE`, which allows a reader to hold an object while appearing "not in epoch" to the reclamation rule, permitting premature freeing.

## What this model is (and isn’t)

- It is a safety model of the lifetime contract around lock-free reads.
- It is not a linearizability model of map update semantics, and it does not model multiple writers/readers.
