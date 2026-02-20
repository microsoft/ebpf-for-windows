# Conformance notes: invoke fast-path loaded-check

## What this model corresponds to

This model captures the essence of the lock-free loaded-check in the invoke fast path:

- In [libs/execution_context/ebpf_program.c](libs/execution_context/ebpf_program.c), `ebpf_program_invoke()` checks `program->extension_program_data` via `ReadPointerNoFence(...)` and bails out if it is `NULL`.
- In [libs/execution_context/ebpf_link.c](libs/execution_context/ebpf_link.c), the link invoke path enters an epoch (`ebpf_epoch_enter(...)`) before calling `ebpf_program_invoke()`.
- In [libs/execution_context/ebpf_program.c](libs/execution_context/ebpf_program.c), the program-information detach path clears `program->extension_program_data` and then calls `ebpf_epoch_synchronize()` when the program is visible to other threads.

## Mapping of model state to implementation concepts

- `ext_ptr` (0/1) represents `program->extension_program_data` being `NULL` or non-`NULL`.
- `ext_alive` represents whether the memory reachable from `extension_program_data` is still valid (not yet freed).
- `DetachClear` models setting `program->extension_program_data = NULL` under the lock/unlock barrier.
- `DetachFree` models freeing the duplicated program data structure (via `ebpf_program_data_free(...)`) after epoch synchronization.

Note: the real detach implementation’s ordering between clearing the pointer, freeing the duplicated program data, and synchronizing epochs is more detailed than this model. This model intentionally treats reclamation as happening only after epoch synchronization to isolate the memory-ordering hazard of a NoFence read without an epoch-enter barrier. If you want to validate use-after-free under a worst-case “detach can overlap invoke” schedule, the model should be extended to reflect the exact ordering and allowed concurrency.
- `InvokerEnterEpoch` models the caller entering an epoch (`ebpf_epoch_enter(...)`).
- `InvokerReadPointerNoFence` models `ReadPointerNoFence(&program->extension_program_data)`.
  - If `EpochEnterIsBarrier=TRUE`, the read must see the current value.
  - If `EpochEnterIsBarrier=FALSE`, the read may see a stale previous value.
- `InvokerUse` abstracts any dereference/use of data reachable from the pointer.

## Key assumption being validated

The safety of using `ReadPointerNoFence` here depends on the documented property:
- entering the epoch provides sufficient ordering so that a NoFence pointer read observes the up-to-date value (or otherwise cannot observe a freed object).

The buggy configuration intentionally violates this assumption by setting `EpochEnterIsBarrier=FALSE`.
