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

The epoch module is implemented as a per-CPU design. Each CPU maintains its own
epoch state and free list. The per-CPU epochs are kept consistent via an inter-CPU
messaging cycle.

At a high level, the epoch module provides:

- A way to mark an execution context as being "in an epoch" (read-side critical section).
- A way to defer frees until it is safe to reclaim memory.
- A way to schedule callbacks to run once an epoch has been retired.

## Core concepts (as implemented)

### Per-CPU state

Each CPU maintains:

- A list of active epoch participants on that CPU (the epoch state list).
- A per-CPU free list containing allocations/work-items waiting to be reclaimed.
- A per-CPU `current_epoch` value.
- A per-CPU `released_epoch` value (the newest epoch that is safe to reclaim).

Although these are per-CPU values, the propose/commit protocol ensures that all CPUs
advance to a consistent `current_epoch` and compute a safe global minimum for release.

Every execution context (a thread at passive IRQL or a DPC running at
dispatch IRQL) is associated with the point in time when execution began
(i.e., the per-CPU `current_epoch` value observed in `ebpf_epoch_enter`).
All memory that the execution context could touch during its execution is part
of that epoch.

### Enter/exit tracking

Callers bracket epoch-protected access with:

- `ebpf_epoch_enter(&epoch_state)`
- `ebpf_epoch_exit(&epoch_state)`

On enter, the epoch module:

- Temporarily raises IRQL to DISPATCH_LEVEL (if needed).
- Captures the current CPU id and that CPU's `current_epoch` into the provided `epoch_state`.
- Inserts `epoch_state` into that CPU's epoch state list.

On exit, the module removes `epoch_state` from the list and may arm a timer to
trigger an epoch computation if there is pending reclamation work.

Special case: if a thread entered an epoch at IRQL < DISPATCH_LEVEL and later
exits on a different CPU, the exit operation is forwarded (via the inter-CPU
work queue) to the CPU where the enter occurred so the correct per-CPU list is updated.

When memory is no longer needed, it is first made non-reachable (all
pointers to it are removed) after which it is stamped with the current
epoch and inserted into a "free list". The timestamp the is point in time
when the memory transitioned from visible -> non-visible and as such
can only be returned to the OS once no active execution context could be
using that memory.

In the implementation, an allocation is stamped with `freed_epoch` at the moment it is queued:

- `freed_epoch = (current CPU's current_epoch)`

and it becomes eligible for reclamation when:

- `freed_epoch <= released_epoch`

where `released_epoch` is computed via the propose/commit epoch computation described below.

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
cycle via the CPU work queues.

### Propose phase

The propose phase walks all CPUs to determine a safe epoch boundary:

- CPU 0 increments its `current_epoch` and initializes `proposed_release_epoch` to that new value.
- Every other CPU sets its `current_epoch` to the value provided by CPU 0.
- Each CPU computes the minimum `epoch` value among active epoch participants on that CPU.
- The message's `proposed_release_epoch` becomes the minimum over all CPUs.

The last CPU converts the message into a commit message and sends it back to CPU 0.

### Commit phase

On commit, each CPU:

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

## Future investigations
The implementation currently performs epoch computations via inter-CPU messaging and
per-CPU list scans. Potential areas for future investigation include:

- Reducing contention or overhead in the propose/commit cycle as CPU count increases.
- Evaluating whether alternative time sources (hardware-backed clocks) can reduce state-change-driven contention,
    noting that QueryPerformanceCounter and its kernel equivalent may have higher overhead than a state-driven clock.