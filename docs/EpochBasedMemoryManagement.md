# Epoch based memory management.

## Overview

The eBPF for Windows project uses an epoch based scheme for managing
memory that permits a certain class of lock free operations,
specifically the ability to implement lock free hash tables and other
structures that require "read copy update" aka RCU semantics.

Epoch driven memory management is an area that has been covered extensively by
academic papers (as an example [Interval-Based Memory Reclamation
(rochester.edu)](https://www.cs.rochester.edu/~scott/papers/2018_PPoPP_IBR.pdf)).
The approach taken in this project is a simplification of several
different approaches outlined in various research papers with the result
being a tradeoff between performance and code complexity.

In the context of this project's epoch memory management module
(referred to as epoch module herein), the term epoch is intended to
mean a period of indeterminate length.

The epoch module is implemented as a per-CPU design for participant tracking and
deferred-reclamation queues. The backing state table is sized for the kernel-reported
maximum logical processor count, while only admitted active CPUs maintain live epoch
state lists and free lists.

Epoch *numbering* is driven by a single globally published epoch value that is advanced
by CPU 0 during an inter-CPU propose/commit cycle. Each admitted CPU also caches this value in a
per-CPU `current_epoch`, which may temporarily lag until it processes the latest message.

At a high level, the epoch module provides:

- A way to mark an execution context as being "in an epoch" (read-side critical section).
- A way to defer frees until it is safe to reclaim memory.
- A way to schedule callbacks to run once an epoch has been retired.

## Core concepts (as implemented)

### Per-CPU state

Each admitted CPU maintains:

- A list of active epoch participants on that CPU (the epoch state list).
- A per-CPU free list containing allocations/work-items waiting to be reclaimed.
- A per-CPU `current_epoch` value (a cache of the globally published epoch).
- A per-CPU `released_epoch` value (the newest epoch that is safe to reclaim).

In addition to the per-admitted-CPU state, there is a globally published epoch value used as the
source of truth for:

- `ebpf_epoch_enter()` stamping the `epoch_state->epoch` value.
- Retirement stamping when an allocation/work item is inserted into a free list.

The propose/commit protocol computes a safe global minimum for release. Per-CPU `current_epoch`
values are synchronized via inter-CPU messaging but may temporarily lag the globally
published epoch.

Every execution context (a thread at passive IRQL or a DPC running at
dispatch IRQL) is associated with the point in time when execution began
(i.e., the globally published epoch value observed in `ebpf_epoch_enter`).
All memory that the execution context could touch during its execution is part
of that epoch.

### Enter/exit tracking

Callers bracket epoch-protected access with:

- `ebpf_epoch_enter(&epoch_state)`
- `ebpf_epoch_exit(&epoch_state)`

On enter, the epoch module:

- Temporarily raises IRQL to DISPATCH_LEVEL (if needed).
- Verifies that the current logical CPU has completed epoch admission.
- Captures the current CPU id and the globally published epoch into the provided `epoch_state`.
- Inserts `epoch_state` into that CPU's admitted epoch state list.

On exit, the module removes `epoch_state` from the list and may arm a timer to
trigger an epoch computation if there is pending reclamation work.

Special case: if a thread entered an epoch at IRQL < DISPATCH_LEVEL and later
exits on a different CPU, the exit operation is forwarded (via the inter-CPU
work queue) to the CPU where the enter occurred so the correct per-CPU list is updated.

### Per-CPU work queues

The epoch module uses a per-CPU *timed work queue* to drive its inter-CPU messaging and to
process certain epoch operations on the correct target CPU.

Each admitted CPU has its own queue. Work items on that queue are processed:

- Opportunistically, when `ebpf_epoch_exit()` flushes the current CPU's queue before returning.
- As a backstop, when the queue's timer expires (batching multiple messages).

This model allows the epoch module to batch background work under load (timer-driven) while still
ensuring prompt processing at key correctness boundaries (exit-driven flush).

When memory is no longer needed, it is first made non-reachable (all
pointers to it are removed) after which it is stamped with the current
epoch and inserted into a "free list". The timestamp the is point in time
when the memory transitioned from visible -> non-visible and as such
can only be returned to the OS once no active execution context could be
using that memory.

In the implementation, an allocation/work item is stamped with `freed_epoch` at the moment it is queued,
using the globally published epoch value (so retirements are never stamped with an epoch older than a
concurrent reader may have observed), and it becomes eligible for reclamation when `freed_epoch <= released_epoch`,
where `released_epoch` is computed via the propose/commit epoch computation described below.

### Active vs. potential (hot-add) CPUs

The per-CPU table is sized for the system's *maximum* processor count. On systems where the maximum
processor count exceeds the set of processors that are actually schedulable at boot (hot-add-capable
firmware, BIOS-disabled cores, partial processor groups), a per-CPU work queue cannot be created for
the non-schedulable indices.

As an **interim stopgap** (full hot-add support is tracked separately), `ebpf_epoch_initiate()` no
longer fails the whole load in this situation. Instead, each per-CPU entry carries an `admitted` flag:
a CPU is *admitted* only if its work queue was successfully created (i.e., the processor is
schedulable). CPU 0 is required — if it cannot be admitted, initialization still fails.

Non-admitted CPUs are handled as follows:

- The inter-CPU propose/commit/rundown ring walk skips non-admitted CPUs (it steps to the next
    admitted CPU, always terminating because CPU 0 is admitted).
- Any code path that touches a non-admitted CPU's per-CPU state (`ebpf_epoch_enter`,
    `ebpf_epoch_exit`, free-list insertion, free-list queries) **fails fast** rather than corrupting
    state.

Because the current CPU of a running thread is always a schedulable (admitted) CPU, this is safe as
long as the non-admitted (inactive/hot-add) CPUs are never brought online and used. If such a CPU is
ever used before full hot-add support lands, the fail-fast guards trip instead of silently corrupting
epoch state.

## Epoch computation (propose/commit)

Reclamation is driven by an epoch computation cycle that is initiated when there are items
waiting on a CPU's free list.

### Triggering

When an item is inserted into a free list (or when an epoch is exited), the CPU may arm a timer
if the following conditions are met:

1. Rundown is not in progress.
2. The timer is not already armed.
3. The local free list is not empty.

The timer's DPC is targeted to CPU 0. When the timer fires, it initiates an epoch computation
cycle by queuing a `PROPOSE_RELEASE_EPOCH` message to CPU 0's per-CPU work queue.
The propose/commit message sequence is then forwarded CPU-by-CPU using the same work queues.

### Propose phase

During the propose phase, the system determines the **safe release epoch** by passing a
`PROPOSE_RELEASE_EPOCH` message sequentially across the admitted active CPU set, starting with CPU 0. The message
carries the proposed release-epoch value.

- CPU 0 atomically increments the globally published current epoch, updates its local current epoch
    cache, and initializes the message's proposed release epoch to that new value.
- Each subsequent admitted CPU updates its local current epoch cache to the value carried in the message.
- Every admitted CPU, including CPU 0, computes the minimum epoch from its local epoch-state list. If this
    minimum is lower than the message's proposed epoch, the message is updated with that lower value.
- The CPU then forwards the (potentially updated) message to the next admitted CPU.

After the final CPU processes the message, it converts it into a `COMMIT_RELEASE_EPOCH` message
containing the final proposed release epoch and sends it back to CPU 0. This begins the commit
phase of the cycle.

### Commit phase

On commit, each admitted CPU:

1. Clears the local `timer_armed` flag.
2. Computes `released_epoch = proposed_release_epoch - 1`.
3. Releases eligible items from the local free list while the head item satisfies `freed_epoch <= released_epoch`.
4. Rearms the timer if there is still pending work.

Finally, an "epoch computation complete" message clears the in-progress flag (on CPU 0)
so another cycle may run.


## Work items

In some cases code that uses the epoch module requires more complex
behavior than simply freeing memory on epoch expiry. To permit this
behavior, the epoch module exposes ebpf_epoch_schedule_work_item which
can be used to run a block of work when it is safe to do so.

This is implemented as a special entry in the free list. When the entry becomes eligible
for reclamation (i.e., `freed_epoch <= released_epoch` on a CPU during commit), the module
queues a preemptible work item that runs the callback on a worker context. The callback
can then perform additional cleanup of state as needed.

## Synchronization

For passive-level callers, the epoch module provides `ebpf_epoch_synchronize()`.
This function blocks until an epoch computation has run and a synchronization object
queued to the epoch free list has been processed, providing a way to wait for previously
queued epoch work to become reclaimable.

**Important:** Work item callbacks run **outside of any epoch** by default.
If a work item callback needs to access epoch-managed data structures
(such as hash tables created with `ebpf_hash_table_create` using the default
epoch-based allocator), the callback must explicitly call `ebpf_epoch_enter()`
and `ebpf_epoch_exit()` to ensure proper epoch protection and avoid
use-after-free issues.

## CPU admission and hot-add

The epoch module distinguishes between:

- The maximum logical CPU count, which sizes the backing epoch table.
- The admitted active CPU set, which participates in epoch entry/exit, retirement, and consensus.

CPUs that are inactive at startup remain backed by preallocated but inactive table entries.
When a CPU becomes active later, the epoch module must complete a CPU-admission sequence before
that CPU can participate in current-CPU epoch operations. The intended design is to use
processor-change notification to initialize the CPU's local queue/state and stage the active
participant-ring update during add-start notification, then publish admission during add-complete
notification once Windows reports that the processor has started.

As a safety backstop, if a current-CPU epoch API is reached on a CPU that has not completed
admission, the implementation must fail fast rather than touching inactive state or blocking
in `ebpf_epoch_enter()`.

## Future investigations
The implementation currently performs epoch computations via inter-CPU messaging and
per-CPU list scans. Potential areas for future investigation include:

- Reducing contention or overhead in the propose/commit cycle as CPU count increases.
- Evaluating whether alternative time sources (hardware-backed clocks) can reduce state-change-driven contention,
    noting that QueryPerformanceCounter and its kernel equivalent may have higher overhead than a state-driven clock.