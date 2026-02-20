# Object Array Map (lock-free read) TLA+ Model

This folder contains a bounded TLA+ model of the lock-free read of an object pointer stored in an array map slot.

This corresponds to the pattern used by:
- program arrays (`BPF_MAP_TYPE_PROG_ARRAY`)
- array-of-maps (`BPF_MAP_TYPE_ARRAY_OF_MAPS`)

## What the model checks

Safety invariant (`Safety`):
- A reader must never hold/use an object that has been freed.

The model captures the key intended contract:
- Readers that load a pointer from the slot must be inside an epoch (or equivalent guard), because object destruction is deferred via an epoch work item when the reference count reaches zero.
- Readers must also stop using any pointers read from the slot before exiting the epoch.

## Files

- `ObjectArrayMapModel.tla`: the model.
- `ObjectArrayMapModel.cfg`: safe configuration (expected to pass).
- `ObjectArrayMapModel_buggy_read_outside_epoch.cfg`: deliberately unsafe configuration (expected to fail `Safety`).

## Running TLC locally

From the repo root:

- Safe model (expected PASS):
  - `"C:\Program Files\Microsoft\jdk-21.0.9.10-hotspot\bin\java.exe" -cp models\tla2tools.jar tlc2.TLC -workers auto models\object_array_map\ObjectArrayMapModel.tla -config models\object_array_map\ObjectArrayMapModel.cfg`

- Buggy model (expected FAIL):
  - `"C:\Program Files\Microsoft\jdk-21.0.9.10-hotspot\bin\java.exe" -cp models\tla2tools.jar tlc2.TLC -workers auto models\object_array_map\ObjectArrayMapModel.tla -config models\object_array_map\ObjectArrayMapModel_buggy_read_outside_epoch.cfg`

## Notes / limitations

- Single reader, single writer, single array slot.
- No attempt to model map locks explicitly; the writer update is modeled as atomic.
- Object reference counts are abstracted: the writer update retires the old object; reclamation happens later when the epoch condition permits.
- The buggy configuration models a contract violation: reading the slot without being in an epoch.
- The safe configuration assumes the reader drops the pointer before exiting the epoch.
