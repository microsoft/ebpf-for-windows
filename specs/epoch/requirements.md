<!-- Copyright (c) eBPF for Windows contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Epoch Module — Requirements Specification

## 1. Overview

The `ebpf_epoch` module implements an **epoch-based memory reclamation (EBR)** system for the
eBPF for Windows kernel runtime. EBR allows concurrent readers to access shared data structures
without locks while guaranteeing that freed memory is not reclaimed until all readers that could
have observed the old state have exited their critical sections.

The module provides:

- **Epoch critical sections** that threads enter/exit to declare participation in the current epoch.
- **Deferred memory reclamation** that stamps freed objects with the epoch at which they were freed
  and releases them only after all CPUs have advanced past that epoch.
- **A three-phase inter-CPU protocol** (PROPOSE → COMMIT → COMPLETE) that computes a safe
  release epoch across all CPUs.
- **Work item scheduling** that defers callback execution until epoch expiry.
- **Synchronous epoch barriers** that block a caller until the current epoch ends.

The module is designed for the Windows kernel environment, operating at IRQL up to DISPATCH_LEVEL,
with per-CPU isolation to minimize cross-CPU contention.

## 2. Scope

### 2.1 In Scope

- Initialization and teardown of the epoch tracking subsystem.
- Epoch critical section entry and exit (including cross-CPU thread migration handling).
- Epoch-tracked memory allocation and deferred free (standard and cache-aligned variants).
- The three-phase epoch computation protocol.
- Epoch work item allocation, scheduling, and cancellation.
- Synchronous epoch barrier (`ebpf_epoch_synchronize`).
- Per-CPU free list diagnostics.
- Thread safety, IRQL constraints, and robustness guarantees.

### 2.2 Out of Scope

- The implementation of underlying platform primitives (`cxplat_*`, `ebpf_allocate`, timers, DPCs).
- eBPF program loading, verification, JIT compilation, or map management.
- The eBPF extension model (NMR hook providers).
- Performance tuning or benchmarking of the epoch subsystem.

## 3. Definitions and Glossary

| Term | Definition |
|------|-----------|
| **Epoch** | A monotonically increasing 64-bit counter representing a logical time interval. All CPUs share a single published epoch value. |
| **Published epoch** | The global epoch counter (`_ebpf_epoch_published_current_epoch`) visible to all CPUs. Incremented during the PROPOSE phase. |
| **Local epoch** | Each CPU's cached copy of the epoch (`current_epoch` in `ebpf_epoch_cpu_entry_t`). Updated from the published epoch during PROPOSE. |
| **Released epoch** | The newest epoch whose freed items MAY safely be reclaimed. Set to `proposed_release_epoch - 1` during the COMMIT phase. |
| **Epoch critical section** | The interval between `ebpf_epoch_enter()` and `ebpf_epoch_exit()` during which a thread declares it may be observing data associated with the epoch it entered at. |
| **Epoch state** | A per-thread structure (`ebpf_epoch_state_t`) recording the epoch at entry, the CPU on which entry occurred, and the saved IRQL. |
| **Free list** | A per-CPU singly-linked list of deferred-free items awaiting epoch expiry. |
| **Freed epoch** | The epoch value stamped on a freed item. The item is eligible for reclamation when `released_epoch >= freed_epoch`. |
| **Epoch computation** | The three-phase inter-CPU protocol that advances the published epoch and determines the safe release epoch. |
| **PROPOSE phase** | Phase 1: CPU 0 increments the published epoch and proposes a release epoch. Each CPU computes the minimum epoch across its active threads. |
| **COMMIT phase** | Phase 2: Each CPU sets its released epoch and releases eligible free-list items. |
| **COMPLETE phase** | Phase 3: CPU 0 clears the computation-in-progress flag or signals synchronous waiters. |
| **Cross-CPU migration** | When a thread enters an epoch critical section on one CPU but exits on a different CPU due to OS thread scheduling. |
| **Rundown** | The graceful shutdown sequence that ensures all deferred work completes before the module is torn down. |
| **Work item** | A callback/context pair scheduled for deferred execution at PASSIVE_LEVEL after the current epoch expires. |
| **DPC** | Deferred Procedure Call — a Windows kernel mechanism for scheduling work at DISPATCH_LEVEL. |
| **IRQL** | Interrupt Request Level — the Windows kernel priority scheme (PASSIVE_LEVEL < APC_LEVEL < DISPATCH_LEVEL). |
| **Cache-aligned** | Memory allocated at an address that is a multiple of the CPU cache line size (`EBPF_CACHE_LINE_SIZE`). |
| **Pool tag** | A 4-byte identifier used by the Windows pool allocator for tracking and debugging allocations. |

## 4. Requirements

### 4.1 Lifecycle (REQ-LIFE-NNN)

**REQ-LIFE-001**: The system MUST allocate and initialize a per-CPU state table when
`ebpf_epoch_initiate()` is called so that each CPU has independent epoch tracking state.
**[High]**

- The per-CPU table MUST be cache-aligned and allocated from non-paged pool with tag
  `EBPF_POOL_TAG_EPOCH`.
- Each CPU entry MUST have its `current_epoch` initialized to 1.
- The global published epoch MUST be set to 1.
- AC-1: After successful `ebpf_epoch_initiate()`, the per-CPU table is non-NULL, each entry's
  `current_epoch` equals 1, and `_ebpf_epoch_published_current_epoch` equals 1.

> Source: `ebpf_epoch.c:259-278`

**REQ-LIFE-002**: The system MUST create a timed work queue per CPU during initialization so that
inter-CPU epoch messages can be delivered.
**[High]**

- AC-1: After successful `ebpf_epoch_initiate()`, each CPU entry's `work_queue` is non-NULL.
- AC-2: If any work queue creation fails, `ebpf_epoch_initiate()` MUST clean up all previously
  allocated resources and return `EBPF_NO_MEMORY`.

> Source: `ebpf_epoch.c:281-308`

**REQ-LIFE-003**: The system MUST initialize a timer and DPC targeted to CPU 0 during
initialization so that epoch computation can be triggered periodically.
**[High]**

- AC-1: After successful `ebpf_epoch_initiate()`, the timer and DPC objects are initialized with
  the DPC targeted to CPU 0.

> Source: `ebpf_epoch.c:294-297`

**REQ-LIFE-004**: `ebpf_epoch_initiate()` MUST return `EBPF_SUCCESS` on success and
`EBPF_NO_MEMORY` if any allocation fails.
**[High]**

- AC-1: On allocation failure, no resources are leaked: all partially allocated resources are freed
  before returning.

> Source: `ebpf_epoch.c:246-311`, `ebpf_epoch.h:29-30`

**REQ-LIFE-005**: `ebpf_epoch_terminate()` MUST perform a complete rundown sequence so that all
deferred work completes before the module is torn down.
**[High]**

- The sequence MUST:
  1. Send a `RUNDOWN_IN_PROGRESS` message to all CPUs and wait for acknowledgement.
  2. Cancel the epoch computation timer.
  3. Flush queued DPCs.
  4. Release all per-CPU free lists using `MAXINT64` as the released epoch (forcing all items to
     be eligible).
  5. Wait for rundown protection to drain (all outstanding work items complete).
  6. Free the per-CPU table and reset global state.
- AC-1: After `ebpf_epoch_terminate()` returns, all per-CPU free lists are empty and the CPU table
  pointer is NULL.

> Source: `ebpf_epoch.c:313-351`

**REQ-LIFE-006**: `ebpf_epoch_terminate()` MUST initialize work item rundown protection during
`ebpf_epoch_initiate()` and wait for all work items to complete during termination so that no
callbacks execute after the module is torn down.
**[High]**

- AC-1: `ebpf_epoch_terminate()` blocks until all previously scheduled work item callbacks have
  returned.

> Source: `ebpf_epoch.c:253, 343`

### 4.2 Epoch Critical Section (REQ-ECS-NNN)

**REQ-ECS-001**: `ebpf_epoch_enter()` MUST record the current published epoch, the CPU ID, and
the caller's IRQL into the provided `ebpf_epoch_state_t` so that the system can track which epoch
each thread is observing.
**[High]**

- AC-1: After `ebpf_epoch_enter()` returns, `epoch_state->epoch` equals the published epoch at
  entry time, `epoch_state->cpu_id` equals the CPU on which entry occurred, and
  `epoch_state->irql_at_enter` equals the caller's original IRQL.

> Source: `ebpf_epoch.c:357-368`, `ebpf_epoch.h:14-20`

**REQ-ECS-002**: `ebpf_epoch_enter()` MUST temporarily raise IRQL to DISPATCH_LEVEL to insert the
epoch state into the per-CPU list, then restore the original IRQL, so that the per-CPU list
manipulation is safe from preemption.
**[High]**

- AC-1: The caller's IRQL is the same before and after `ebpf_epoch_enter()`.
- AC-2: The epoch state is inserted into the per-CPU `epoch_state_list` of the CPU where entry
  occurred.

> Source: `ebpf_epoch.c:360-367`, `ebpf_epoch.h:43-44` (`_IRQL_requires_same_`)

**REQ-ECS-003**: `ebpf_epoch_exit()` MUST remove the epoch state from the per-CPU list and restore
the original IRQL so that the thread is no longer blocking epoch advancement on that CPU.
**[High]**

- AC-1: The caller's IRQL is the same before and after `ebpf_epoch_exit()`.
- AC-2: The epoch state is no longer present in any per-CPU `epoch_state_list`.

> Source: `ebpf_epoch.c:375-422`, `ebpf_epoch.h:50-51` (`_IRQL_requires_same_`)

**REQ-ECS-004**: `ebpf_epoch_exit()` MUST detect cross-CPU migration (when the current CPU differs
from `epoch_state->cpu_id`) and send an `EXIT_EPOCH` message to the original CPU so that the epoch
state is removed from the correct per-CPU list.
**[High]**

- AC-1: When a thread that entered on CPU A exits on CPU B (A ≠ B), the epoch state is correctly
  removed from CPU A's list.
- AC-2: The exit operation completes successfully regardless of which CPU the thread migrated to.

> Source: `ebpf_epoch.c:386-412`

**REQ-ECS-005**: `ebpf_epoch_exit()` MUST fail-fast if cross-CPU migration is detected and the
original IRQL at entry was DISPATCH_LEVEL, because thread migration at DISPATCH_LEVEL is not
possible under normal operation and indicates corruption.
**[High]**

- AC-1: If `epoch_state->irql_at_enter == DISPATCH_LEVEL` and the current CPU differs from
  `epoch_state->cpu_id`, the system calls `EBPF_EPOCH_FAIL_FAST`.

> Source: `ebpf_epoch.c:389`

**REQ-ECS-006**: `ebpf_epoch_exit()` MUST arm the epoch computation timer after removing the epoch
state so that freed items can be reclaimed in a timely manner.
**[High]**

- AC-1: If the per-CPU free list is non-empty after exit, the timer is armed (or was already
  armed).

> Source: `ebpf_epoch.c:415`

### 4.3 Memory Management (REQ-MEM-NNN)

**REQ-MEM-001**: `ebpf_epoch_allocate()` and `ebpf_epoch_allocate_with_tag()` MUST prepend an
`ebpf_epoch_allocation_header_t` to each allocation so that the system can track the freed epoch
and entry type for deferred reclamation.
**[High]**

- The header MUST contain: a list entry for the free list, a `freed_epoch` field (initialized to 0),
  and an `entry_type` field.
- The pointer returned to the caller MUST point past the header.
- AC-1: The returned pointer is offset from the actual allocation start by
  `sizeof(ebpf_epoch_allocation_header_t)`.
- AC-2: The `freed_epoch` field of a newly allocated item is 0.

> Source: `ebpf_epoch.c:427-445`, `ebpf_epoch.c:189-194`

**REQ-MEM-002**: `ebpf_epoch_allocate_cache_aligned_with_tag()` MUST return a cache-line-aligned
pointer and prepend a header of at least `EBPF_CACHE_LINE_SIZE` bytes so that the allocation is
suitable for per-CPU data structures that must avoid false sharing.
**[High]**

- AC-1: The returned pointer is aligned to `EBPF_CACHE_LINE_SIZE`.
- AC-2: The header is located exactly one cache line before the returned pointer.

> Source: `ebpf_epoch.c:448-460`

**REQ-MEM-003**: `ebpf_epoch_allocate()`, `ebpf_epoch_allocate_with_tag()`, and
`ebpf_epoch_allocate_cache_aligned_with_tag()` MUST return NULL if the underlying allocator fails
so that callers can handle out-of-memory conditions.
**[High]**

- AC-1: When the underlying `ebpf_allocate_with_tag` or `ebpf_allocate_cache_aligned_with_tag`
  returns NULL, the epoch allocate function returns NULL without side effects.

> Source: `ebpf_epoch.c:433-434, 454-455`

**REQ-MEM-004**: `ebpf_epoch_free()` MUST NOT immediately release memory. Instead, it MUST insert
the allocation into the per-CPU free list for deferred reclamation so that concurrent readers in
older epochs can safely continue accessing the data.
**[High]**

- The entry type MUST be set to `EBPF_EPOCH_ALLOCATION_MEMORY`.
- AC-1: After `ebpf_epoch_free()`, the allocation header is present in the per-CPU free list.
- AC-2: The memory is not returned to the pool allocator until the epoch computation determines it
  is safe.

> Source: `ebpf_epoch.c:463-478`

**REQ-MEM-005**: `ebpf_epoch_free_cache_aligned()` MUST insert the cache-aligned allocation into
the per-CPU free list with entry type `EBPF_EPOCH_ALLOCATION_MEMORY_CACHE_ALIGNED` so that the
correct deallocation function is used during reclamation.
**[High]**

- AC-1: During reclamation, items of this type are freed via `ebpf_free_cache_aligned()`, not
  `ebpf_free()`.

> Source: `ebpf_epoch.c:481-496, 617-619`

**REQ-MEM-006**: When inserting an item into the free list, the system MUST stamp `freed_epoch` as
`max(published_epoch, local_epoch)` so that the item is not reclaimed prematurely if the local CPU
has a stale view of the epoch.
**[High]**

- AC-1: `freed_epoch` is always ≥ the published epoch at the time of the free call.
- AC-2: `freed_epoch` is always ≥ the local CPU's `current_epoch`.

> Source: `ebpf_epoch.c:704-706`

**REQ-MEM-007**: `ebpf_epoch_free()` MUST treat a NULL pointer as a no-op so that callers are not
required to check for NULL before freeing.
**[High]**

- AC-1: Calling `ebpf_epoch_free(NULL)` returns immediately without side effects.

> Source: `ebpf_epoch.c:467-469`

**REQ-MEM-008**: `ebpf_epoch_free_cache_aligned()` MUST treat a NULL pointer as a no-op.
**[High]**

- AC-1: Calling `ebpf_epoch_free_cache_aligned(NULL)` returns immediately without side effects.

> Source: `ebpf_epoch.c:485-487` (analogous NULL check)

**REQ-MEM-009**: During free-list release, the system MUST only reclaim items whose `freed_epoch`
is less than or equal to the `released_epoch` so that items freed in newer epochs are retained
until it is safe.
**[High]**

- AC-1: No item with `freed_epoch > released_epoch` is reclaimed.
- AC-2: All items with `freed_epoch <= released_epoch` at the head of the free list are reclaimed
  in a single pass.

> Source: `ebpf_epoch.c:590-631`

**REQ-MEM-010**: During free-list release, items of type `EBPF_EPOCH_ALLOCATION_MEMORY` MUST be
freed via `ebpf_free()`, and items of type `EBPF_EPOCH_ALLOCATION_MEMORY_CACHE_ALIGNED` MUST be
freed via `ebpf_free_cache_aligned()`.
**[High]**

- AC-1: Each memory entry type uses its corresponding deallocation function.
- AC-2: An unrecognized entry type causes a fail-fast.

> Source: `ebpf_epoch.c:603-622`

### 4.4 Epoch Computation (REQ-COMP-NNN)

**REQ-COMP-001**: The epoch computation protocol MUST use a three-phase sequential inter-CPU
message-passing scheme (PROPOSE → COMMIT → COMPLETE) so that all CPUs reach consensus on the
release epoch before any reclamation occurs.
**[High]**

- AC-1: The PROPOSE message is initiated on CPU 0 and forwarded sequentially to each CPU.
- AC-2: The COMMIT message is initiated by the last CPU and forwarded sequentially back through
  all CPUs.
- AC-3: The COMPLETE message is processed by CPU 0 to finalize the computation.

> Source: `ebpf_epoch.c:777-888`

**REQ-COMP-002**: During the PROPOSE phase, CPU 0 MUST atomically increment the global published
epoch via `InterlockedIncrement64` so that the epoch advances in a thread-safe manner.
**[High]**

- AC-1: The published epoch is incremented exactly once per epoch computation cycle.

> Source: `ebpf_epoch.c:786-788`

**REQ-COMP-003**: During the PROPOSE phase, each CPU MUST compute the minimum epoch across all
threads in its `epoch_state_list` and reduce the proposed release epoch to this minimum so that no
thread's observed epoch is skipped.
**[High]**

- AC-1: If any thread on a CPU is observing epoch N, the proposed release epoch for that cycle is
  at most N.
- AC-2: If no threads are active on a CPU, that CPU does not reduce the proposed release epoch.

> Source: `ebpf_epoch.c:797-810`

**REQ-COMP-004**: The last CPU in the PROPOSE chain (CPU `_ebpf_epoch_cpu_count - 1`) MUST convert
the PROPOSE message to a COMMIT message and send it to CPU 0 so that the commit phase begins.
**[High]**

- AC-1: The message type changes from `PROPOSE_RELEASE_EPOCH` to `COMMIT_RELEASE_EPOCH`.
- AC-2: The message is sent to CPU 0 to begin the sequential COMMIT pass.

> Source: `ebpf_epoch.c:813-818`

**REQ-COMP-005**: During the COMMIT phase, each CPU MUST set its `released_epoch` to
`proposed_release_epoch - 1` and release eligible free-list items so that memory is reclaimed as
soon as it is safe.
**[High]**

- The subtraction of 1 ensures that items freed in the just-proposed epoch are NOT reclaimed in
  this cycle.
- AC-1: After the COMMIT phase, each CPU's `released_epoch` equals `proposed_release_epoch - 1`.
- AC-2: All free-list items with `freed_epoch <= released_epoch` are reclaimed.

> Source: `ebpf_epoch.c:847-862`

**REQ-COMP-006**: During the COMMIT phase, each CPU MUST clear its `timer_armed` flag so that the
timer can be re-armed if new items are added to the free list.
**[High]**

- AC-1: After processing a COMMIT message, `timer_armed` is `false` on that CPU.

> Source: `ebpf_epoch.c:847`

**REQ-COMP-007**: During the COMPLETE phase, if the computation was triggered by the timer DPC,
CPU 0 MUST clear the `epoch_computation_in_progress` flag so that a new computation cycle can
begin.
**[High]**

- AC-1: After COMPLETE, the system is ready to begin a new epoch computation.

> Source: `ebpf_epoch.c:877-882`

**REQ-COMP-008**: During the COMPLETE phase, if the computation was triggered by a synchronous
caller (`ebpf_epoch_synchronize`), the system MUST signal the completion event instead of clearing
the in-progress flag so that the blocked caller can proceed.
**[High]**

- AC-1: A caller blocked in `ebpf_epoch_synchronize()` is unblocked upon COMPLETE.

> Source: `ebpf_epoch.c:884-886`

### 4.5 Work Items (REQ-WI-NNN)

**REQ-WI-001**: `ebpf_epoch_allocate_work_item()` MUST allocate a work item structure containing
a callback, a callback context, and a preemptible work item, and MUST acquire rundown protection,
so that the callback can be safely deferred to epoch expiry.
**[High]**

- AC-1: The returned work item is non-NULL on success and NULL on failure.
- AC-2: Rundown protection is held for the lifetime of the work item.

> Source: `ebpf_epoch.c:498-524`

**REQ-WI-002**: `ebpf_epoch_allocate_work_item()` MUST return NULL if rundown protection cannot be
acquired (i.e., the module is shutting down) so that callers do not schedule work during teardown.
**[High]**

- AC-1: If `cxplat_acquire_rundown_protection` fails, `NULL` is returned and no resources are
  leaked.

> Source: `ebpf_epoch.c:510-512`

**REQ-WI-003**: `ebpf_epoch_schedule_work_item()` MUST insert the work item into the per-CPU free
list so that the callback is invoked when the current epoch expires.
**[High]**

- The work item header's `entry_type` MUST be set to `EBPF_EPOCH_ALLOCATION_WORK_ITEM`.
- AC-1: After scheduling, the work item is present in the free list and will be processed during
  the next eligible free-list release.

> Source: `ebpf_epoch.c:526-531`

**REQ-WI-004**: When a work item is released from the free list (epoch has expired), the system
MUST queue a preemptible work item that invokes the user callback at PASSIVE_LEVEL so that the
callback can perform operations not permitted at DISPATCH_LEVEL.
**[High]**

- AC-1: The callback is invoked with the context pointer provided at allocation time.
- AC-2: The callback executes at PASSIVE_LEVEL.

> Source: `ebpf_epoch.c:606-610, 1051-1061`

**REQ-WI-005**: After the work item callback completes, the system MUST free the preemptible work
item, free the work item structure, and release rundown protection so that teardown can proceed.
**[High]**

- AC-1: No memory is leaked after the callback returns.
- AC-2: Rundown protection is released exactly once per work item.

> Source: `ebpf_epoch.c:1054-1060`

**REQ-WI-006**: `ebpf_epoch_cancel_work_item()` MUST free the work item and release rundown
protection without invoking the callback so that allocated-but-not-scheduled work items can be
cleaned up.
**[High]**

- AC-1: The callback is NOT invoked.
- AC-2: The preemptible work item and work item structure are freed.
- AC-3: Rundown protection is released.

> Source: `ebpf_epoch.c:533-547`

**REQ-WI-007**: `ebpf_epoch_cancel_work_item()` MUST accept NULL and treat it as a no-op so that
callers are not required to check for NULL before cancelling.
**[Medium]**

- AC-1: Calling `ebpf_epoch_cancel_work_item(NULL)` returns without side effects.

> Source: `ebpf_epoch.h:125-126` (`_In_opt_` annotation)

**REQ-WI-008**: `ebpf_epoch_cancel_work_item()` MUST assert that the work item has not already
been scheduled (inserted into the free list) so that double-schedule bugs are caught during
development.
**[High]**

- AC-1: If the work item has been scheduled, the assertion fails (debug-only check).

> Source: `ebpf_epoch.c:541`

### 4.6 Synchronization (REQ-SYNC-NNN)

**REQ-SYNC-001**: `ebpf_epoch_synchronize()` MUST block the calling thread until the current epoch
has ended and all items freed before the call are eligible for reclamation, so that callers can
guarantee that deferred frees have been processed.
**[High]**

- AC-1: When `ebpf_epoch_synchronize()` returns, all items that were in the free list at the time
  of the call have been released (or are eligible for release).

> Source: `ebpf_epoch.c:549-569`

**REQ-SYNC-002**: `ebpf_epoch_synchronize()` MUST be callable only at IRQL ≤ PASSIVE_LEVEL because
it blocks the calling thread.
**[High]**

- AC-1: The `_IRQL_requires_max_(PASSIVE_LEVEL)` annotation is present.
- AC-2: Calling at DISPATCH_LEVEL or higher results in undefined behavior (a bug).

> Source: `ebpf_epoch.h:95`

**REQ-SYNC-003**: `ebpf_epoch_synchronize()` MUST use a stack-allocated synchronization entry
inserted into the free list, combined with a KEVENT wait, so that no heap allocation is required
for synchronization.
**[High]**

- The synchronization entry's type MUST be `EBPF_EPOCH_ALLOCATION_SYNCHRONIZATION`.
- AC-1: The implementation allocates the synchronization entry on the stack (no heap allocation).
- AC-2: The KEVENT is signaled during free-list release when the synchronization entry's
  `freed_epoch <= released_epoch`.

> Source: `ebpf_epoch.c:556-568`

**REQ-SYNC-004**: `ebpf_epoch_synchronize()` MUST trigger a synchronous PROPOSE message to initiate
an epoch computation cycle so that the epoch advances without waiting for the next timer tick.
**[High]**

- AC-1: The epoch computation is triggered immediately, not deferred to the timer.

> Source: `ebpf_epoch.c:563-566`

### 4.7 Diagnostics (REQ-DIAG-NNN)

**REQ-DIAG-001**: `ebpf_epoch_is_free_list_empty()` MUST return `true` if the specified CPU's free
list is empty and `false` otherwise, so that tests and diagnostics can verify reclamation progress.
**[High]**

- AC-1: The function sends an `IS_FREE_LIST_EMPTY` message to the target CPU and returns the
  result.
- AC-2: The result accurately reflects the state of the free list at the time the message is
  processed on the target CPU.

> Source: `ebpf_epoch.c:571-582`, `ebpf_epoch.h:135-136`

### 4.8 Thread Safety and Concurrency (REQ-TS-NNN)

**REQ-TS-001**: All per-CPU state (epoch state list, free list, flags) MUST be accessed only at
DISPATCH_LEVEL or via inter-CPU messages so that no locking is required for per-CPU data.
**[High]**

- AC-1: `ebpf_epoch_enter()` and `ebpf_epoch_exit()` raise to DISPATCH_LEVEL before manipulating
  per-CPU lists.
- AC-2: Cross-CPU operations use the timed work queue messaging system.

> Source: `ebpf_epoch.c:360, 378, 386-412`

**REQ-TS-002**: The per-CPU state table MUST be cache-line-aligned (`__declspec(align(EBPF_CACHE_LINE_SIZE))`)
so that per-CPU entries do not share cache lines (avoiding false sharing).
**[High]**

- AC-1: The `ebpf_epoch_cpu_entry_t` struct is declared with cache-line alignment.
- AC-2: The table allocation uses cache-aligned allocation.

> Source: `ebpf_epoch.c:60, 259-262`

**REQ-TS-003**: The global published epoch MUST be accessed using acquire/release semantics or
interlocked operations so that epoch values are consistently visible across CPUs.
**[High]**

- AC-1: `InterlockedIncrement64` is used to advance the epoch in the PROPOSE phase.
- AC-2: Acquire-fence reads are used when entering an epoch critical section.

> Source: `ebpf_epoch.c:786, 364`

**REQ-TS-004**: The inter-CPU message-passing system MUST ensure that messages are processed on
the target CPU at DISPATCH_LEVEL so that per-CPU state is safely accessed.
**[High]**

- AC-1: Messages are delivered via timed work queues, which execute at DISPATCH_LEVEL.

> Source: `ebpf_epoch.c:281-292, 980-999`

**REQ-TS-005**: The epoch computation MUST be serialized: only one computation cycle MAY be in
progress at any time, controlled by the `epoch_computation_in_progress` flag on CPU 0.
**[High]**

- AC-1: The timer DPC does not initiate a new computation if one is already in progress.
- AC-2: The COMPLETE phase clears the flag to allow the next computation.

> Source: `ebpf_epoch.c:68, 877-882, 728-754`

### 4.9 Robustness (REQ-ROB-NNN)

**REQ-ROB-001**: `ebpf_epoch_free()` MUST fail-fast if the `freed_epoch` field is non-zero
(indicating a double-free) so that memory corruption is detected immediately rather than causing
silent data corruption.
**[High]**

- AC-1: Calling `ebpf_epoch_free()` on an already-freed pointer triggers
  `FAST_FAIL_HEAP_METADATA_CORRUPTION`.

> Source: `ebpf_epoch.c:474`

**REQ-ROB-002**: `ebpf_epoch_free_cache_aligned()` MUST fail-fast if the `freed_epoch` field is
non-zero (indicating a double-free).
**[High]**

- AC-1: Calling `ebpf_epoch_free_cache_aligned()` on an already-freed pointer triggers
  `FAST_FAIL_HEAP_METADATA_CORRUPTION`.

> Source: `ebpf_epoch.c:492`

**REQ-ROB-003**: During free-list release, an unrecognized `entry_type` MUST trigger a fail-fast so
that corruption of the free list is detected immediately.
**[High]**

- AC-1: The `default` case in the entry-type switch calls `EBPF_EPOCH_FAIL_FAST`.

> Source: `ebpf_epoch.c:622`

**REQ-ROB-004**: The epoch computation timer MUST use a 1 ms delay
(`EBPF_EPOCH_FLUSH_DELAY_IN_NANOSECONDS = 1000000`) so that deferred frees are reclaimed promptly
without excessive CPU overhead.
**[High]**

- AC-1: The timer fires 1 ms after being armed.

> Source: `ebpf_epoch.c:46`

**REQ-ROB-005**: The timer MUST NOT be armed if any of the following conditions are true: (a)
rundown is in progress, (b) the timer is already armed, or (c) the free list is empty; so that
unnecessary timer firings are avoided and shutdown is not delayed.
**[High]**

- AC-1: `_ebpf_epoch_arm_timer_if_needed()` returns without arming if any of the three conditions
  is true.

> Source: `ebpf_epoch.c:641-657`

**REQ-ROB-006**: During termination, the system MUST release all free-list items using `MAXINT64`
as the released epoch so that all deferred frees are processed regardless of their `freed_epoch`.
**[High]**

- AC-1: After the termination release pass, every per-CPU free list is empty.

> Source: `ebpf_epoch.c:334-340`

**REQ-ROB-007**: The system MUST NOT reclaim memory while any thread is in an epoch critical
section observing an epoch ≤ the item's `freed_epoch`, so that use-after-free is prevented.
**[High]**

- AC-1: The `epoch_test_epoch_skew_reclamation_hazard` test validates that no work item callback
  fires while a reader thread is active in a newer epoch.
- AC-2: The `epoch_test_spin_reclamation_stress` test validates that no use-after-free occurs under
  sustained concurrent reader/writer load.

> Source: `platform_unit_test.cpp:749-977, 994-1244`

## 5. Dependencies (DEP-NNN)

**DEP-001**: The module depends on the platform abstraction layer (`cxplat_*`) for timed work
queues, preemptible work items, and rundown references.
**[High]**

> Source: `ebpf_epoch.c:281, 510, 253`

**DEP-002**: The module depends on `ebpf_allocate_with_tag()` and `ebpf_allocate_cache_aligned_with_tag()`
for underlying memory allocation from non-paged pool.
**[High]**

> Source: `ebpf_epoch.c:433, 453`

**DEP-003**: The module depends on Windows kernel primitives: `KTIMER`, `KDPC`,
`KeRaiseIrqlToDpcLevel`, `KeLowerIrql`, `KEVENT`, `KeSetEvent`, `KeWaitForSingleObject`.
**[High]**

> Source: `ebpf_epoch.c:160, 170, 360, 367, 559, 568`

**DEP-004**: The module depends on `KeQueryActiveProcessorCountEx` (or equivalent) to determine the
CPU count at initialization time.
**[High]**

> Source: `ebpf_epoch.c:255`

## 6. Assumptions (ASM-NNN)

**ASM-001**: The number of CPUs does not change after `ebpf_epoch_initiate()` is called. The per-CPU
table size is fixed at initialization.
**[High]**

> Source: `ebpf_epoch.c:255, 259-262`

**ASM-002**: Threads do not hold epoch critical sections indefinitely. Long-held epoch critical
sections block epoch advancement and prevent memory reclamation.
**[Medium]**

> Source: `ebpf_epoch.c:797-810` (minimum epoch computation)

**ASM-003**: `ebpf_epoch_initiate()` is called exactly once before any other epoch API, and
`ebpf_epoch_terminate()` is called exactly once during shutdown. No concurrent calls to initiate
or terminate are permitted.
**[High]**

> Source: `ebpf_epoch.c:246-351` (no internal serialization of init/terminate)

**ASM-004**: Memory returned by the underlying allocators (`ebpf_allocate_with_tag`) is
zero-initialized, ensuring `freed_epoch` starts at 0 for new allocations.
**[High]**

> Source: `ebpf_epoch.c:474` (double-free check relies on `freed_epoch == 0` for fresh allocations)

**ASM-005**: The timed work queue executes message handlers on the target CPU at DISPATCH_LEVEL,
ensuring per-CPU state access is safe without additional locking.
**[High]**

> Source: `ebpf_epoch.c:980-999`

## 7. Risks (RISK-NNN)

**RISK-001**: **Epoch starvation**. If a thread holds an epoch critical section for an extended
period, no memory freed during that time can be reclaimed, potentially leading to unbounded memory
growth. Mitigation: callers SHOULD minimize time spent in epoch critical sections.
**[Medium]**

> Source: `ebpf_epoch.c:797-810`

**RISK-002**: **Cross-CPU exit overhead**. When a thread migrates to a different CPU between
`ebpf_epoch_enter()` and `ebpf_epoch_exit()`, the exit path requires an inter-CPU message round
trip, which is significantly more expensive than a local exit. Mitigation: this is expected to be
rare under normal operation.
**[Medium]**

> Source: `ebpf_epoch.c:386-412`

**RISK-003**: **Timer coalescing / delay**. The 1 ms epoch flush timer relies on the OS timer
subsystem. Under heavy load or timer coalescing, the actual delay may exceed 1 ms, delaying
reclamation. Mitigation: `ebpf_epoch_synchronize()` triggers immediate epoch computation without
waiting for the timer.
**[Low]**

> Source: `ebpf_epoch.c:46, 549-569`

**RISK-004**: **CPU hot-add**. The per-CPU table is allocated once at initialization with a fixed
size. If CPUs are added to the system after initialization, the new CPUs are not tracked. This is
currently mitigated by ASM-001.
**[Low]**

> Source: `ebpf_epoch.c:255, 259-262`

## 8. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-30 | Copilot (spec-extraction) | Initial extraction from codebase |
