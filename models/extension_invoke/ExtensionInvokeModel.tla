\* Copyright (c) eBPF for Windows contributors
\* SPDX-License-Identifier: MIT

---- MODULE ExtensionInvokeModel ----
EXTENDS Naturals, TLC

(*****************************************************************
Bounded, executable TLA+ model of the lock-free "is the extension
still loaded?" check in the invoke fast path.

Source motivation:
- ebpf_program_invoke() checks program->extension_program_data via
  ReadPointerNoFence() and bails out if it's NULL.
- The caller (e.g., ebpf_link invoke path) enters an epoch before
  invoking; ebpf_epoch_enter is documented as a full memory barrier.
- Detach/unload clears extension_program_data under a lock/unlock
  barrier and then synchronizes epochs before proceeding.

What this model focuses on:
- Whether a NoFence pointer read is safe when ordered by an epoch-enter
  barrier.

This model is intentionally small and does not model:
- NMR semantics, provider/client call ordering, or IRQL constraints
- explicit rundown reference protection (ExAcquireRundownProtection)
- multiple concurrent invokers
- actual pointer values (uses 0/1) or program info contents
*****************************************************************)

CONSTANTS
  EpochEnterIsBarrier \* BOOLEAN: if TRUE, entering an epoch provides a full barrier.

ASSUME EpochEnterIsBarrier \in BOOLEAN

Ptr == {0, 1}

VARIABLES
  ext_ptr,        \* 0 means NULL, 1 means non-NULL (loaded)
  stale_ptr,      \* last seen value of ext_ptr (models a potentially stale cached value)
  ext_alive,      \* TRUE if the pointed-to data is still valid (not freed)
  inv_in_epoch,   \* invoker is executing inside an epoch
  inv_barrier,    \* whether the invoker has executed an ordering barrier
  inv_loaded_ptr, \* value read by ReadPointerNoFence
  inv_using       \* invoker is using the extension program data

Vars == <<ext_ptr, stale_ptr, ext_alive, inv_in_epoch, inv_barrier, inv_loaded_ptr, inv_using>>

TypeOK ==
  /\ ext_ptr \in Ptr
  /\ stale_ptr \in Ptr
  /\ ext_alive \in BOOLEAN
  /\ inv_in_epoch \in BOOLEAN
  /\ inv_barrier \in BOOLEAN
  /\ inv_loaded_ptr \in Ptr
  /\ inv_using \in BOOLEAN

(*****************************************************************
Initialization: extension is loaded and its program data is alive.
*****************************************************************)
Init ==
  /\ ext_ptr = 1
  /\ stale_ptr = 1
  /\ ext_alive = TRUE
  /\ inv_in_epoch = FALSE
  /\ inv_barrier = FALSE
  /\ inv_loaded_ptr = 0
  /\ inv_using = FALSE

(*****************************************************************
Detach/unload actions.

We model the "clear pointer" step and the "free program data" step.
The free step is gated by "no invoker currently in an epoch", which is
an abstraction of ebpf_epoch_synchronize().
*****************************************************************)
DetachClear ==
  /\ ext_ptr = 1
  /\ ext_ptr' = 0
  /\ stale_ptr' = ext_ptr
  /\ UNCHANGED <<ext_alive, inv_in_epoch, inv_barrier, inv_loaded_ptr, inv_using>>

DetachFree ==
  /\ ext_ptr = 0
  /\ ext_alive = TRUE
  /\ inv_in_epoch = FALSE
  /\ ext_alive' = FALSE
  /\ UNCHANGED <<ext_ptr, stale_ptr, inv_in_epoch, inv_barrier, inv_loaded_ptr, inv_using>>

(*****************************************************************
Invoker actions.

The invoke fast path performs a NoFence read of ext_ptr.
- If the invoker has a barrier (inv_barrier = TRUE), it must read the
  current value of ext_ptr.
- If the invoker does NOT have a barrier, it may read a stale value.

The model then allows the invoker to "use" the data only if the loaded
pointer is non-NULL.
*****************************************************************)
InvokerEnterEpoch ==
  /\ inv_in_epoch = FALSE
  /\ inv_in_epoch' = TRUE
  /\ inv_barrier' = EpochEnterIsBarrier
  /\ UNCHANGED <<ext_ptr, stale_ptr, ext_alive, inv_loaded_ptr, inv_using>>

InvokerReadPointerNoFence ==
  /\ inv_in_epoch = TRUE
  /\ inv_loaded_ptr = 0
  /\ inv_using = FALSE
  /\ IF inv_barrier
        THEN inv_loaded_ptr' = ext_ptr
        ELSE inv_loaded_ptr' \in {ext_ptr, stale_ptr}
  /\ UNCHANGED <<ext_ptr, stale_ptr, ext_alive, inv_in_epoch, inv_barrier, inv_using>>

InvokerUse ==
  /\ inv_in_epoch = TRUE
  /\ inv_loaded_ptr = 1
  /\ inv_using = FALSE
  /\ inv_using' = TRUE
  /\ UNCHANGED <<ext_ptr, stale_ptr, ext_alive, inv_in_epoch, inv_barrier, inv_loaded_ptr>>

InvokerFinish ==
  /\ inv_in_epoch = TRUE
  /\ inv_using' = FALSE
  /\ inv_loaded_ptr' = 0
  /\ inv_in_epoch' = FALSE
  /\ inv_barrier' = FALSE
  /\ UNCHANGED <<ext_ptr, stale_ptr, ext_alive>>

Next ==
  DetachClear
  \/ DetachFree
  \/ InvokerEnterEpoch
  \/ InvokerReadPointerNoFence
  \/ InvokerUse
  \/ InvokerFinish

Spec == Init /\ [][Next]_Vars

(*****************************************************************
Safety property: the invoker must never use freed extension data.
*****************************************************************)
Safety == inv_using => ext_alive

====
