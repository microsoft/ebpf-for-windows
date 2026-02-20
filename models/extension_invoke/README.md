# Invoke fast-path "extension still loaded?" TLA+ Model

This folder contains a bounded TLA+ model of the lock-free loaded-check in the invoke fast path:

- `ebpf_program_invoke()` checks `program->extension_program_data` via a `ReadPointerNoFence(...)` and returns `EBPF_EXTENSION_FAILED_TO_LOAD` if it is `NULL`.
- The high-volume invoke callers (e.g., link invoke) enter an epoch before calling `ebpf_program_invoke()`.
- The code comments rely on `ebpf_epoch_enter` being a full memory barrier, making the `ReadPointerNoFence` safe when performed after entering the epoch.

## What the model checks

Safety invariant (`Safety`):
- The invoker must never use extension program data after it has been freed.

The model demonstrates why the barrier property matters:
- If epoch-enter is a real barrier, the NoFence read must observe the current pointer value.
- If epoch-enter is *not* a barrier, the NoFence read may observe a stale non-`NULL` pointer even after unload has cleared the pointer and freed the data.

## Files

- `ExtensionInvokeModel.tla`: the model.
- `ExtensionInvokeModel.cfg`: safe configuration (expected to pass).
- `ExtensionInvokeModel_buggy_epoch_enter_not_barrier.cfg`: deliberately unsafe configuration (expected to fail `Safety`).

## Running TLC locally

From the repo root:

- Safe model (expected PASS):
  - `"C:\Program Files\Microsoft\jdk-21.0.9.10-hotspot\bin\java.exe" -cp models\tla2tools.jar tlc2.TLC -workers auto models\extension_invoke\ExtensionInvokeModel.tla -config models\extension_invoke\ExtensionInvokeModel.cfg`

- Buggy model (expected FAIL):
  - `"C:\Program Files\Microsoft\jdk-21.0.9.10-hotspot\bin\java.exe" -cp models\tla2tools.jar tlc2.TLC -workers auto models\extension_invoke\ExtensionInvokeModel.tla -config models\extension_invoke\ExtensionInvokeModel_buggy_epoch_enter_not_barrier.cfg`

## Notes / limitations

- Single invoker and a single extension program data pointer.
- Abstracts pointer values to `0/1` and models "stale reads" as nondeterministically returning the last value.
- Abstracts `ebpf_epoch_synchronize()` as "free is only allowed when no invoker is currently in an epoch".
- The real detach path in the code does additional steps (lock/unlock barrier, rundown wait, etc.) and its exact free/clear ordering is not modeled here; this model is narrowly focused on the ordering requirement behind using `ReadPointerNoFence`.
- Does not model rundown protection or NMR call ordering.
