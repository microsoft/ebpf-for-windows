<!-- Copyright (c) eBPF for Windows contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Epoch Module — Design Specification

## 1. Overview

The `ebpf_epoch` module implements an **epoch-based memory reclamation** (EBR)
system for the eBPF for Windows project. It provides safe, deferred memory
reclamation that allows lock-free data structures — particularly hash tables and
other structures requiring Read-Copy-Update (RCU) semantics — to operate
without holding global locks during reads. **[High]**
(`docs/EpochBasedMemoryManagement.md:1-15`, `ebpf_epoch.c:28-41`)

### Design Philosophy

The implementation is a deliberate simplification of academic EBR/IBR schemes
(e.g., [Interval-Based Memory Reclamation — Rochester, 2018](https://www.cs.rochester.edu/~scott/papers/2018_PPoPP_IBR.pdf)),
trading some theoretical optimality for reduced code complexity. **[High]**
(`docs/EpochBasedMemoryManagement.md:10-15`)

### Goals

| Goal | Mechanism |
|------|-----------|
| Lock-free read-side critical sections | Per-CPU epoch state lists — no locks at `DISPATCH_LEVEL` |
| Safe deferred reclamation | Items stamped with `freed_epoch`, released only when no reader can reference them |
| Per-CPU isolation | Each CPU owns its state exclusively at `IRQL >= DISPATCH_LEVEL`, eliminating false sharing |
| Minimal global synchronization | Single `InterlockedIncrement` per epoch advance; remaining coordination via DPC messages |
| Extensibility | Work-item and synchronization callbacks built atop the same free-list mechanism |

## 2. Requirements Summary

The canonical requirements are defined in `specs/epoch/requirements.md`. The
table below maps key requirements to the design sections that address them.

| REQ-ID | Requirement Summary | Design Section |
|--------|---------------------|----------------|
| REQ-ROB-007 | No reclamation while any reader holds epoch reference | §4.3, §4.4, §4.10 |
| REQ-ECS-002, REQ-TS-001 | IRQL handling for epoch enter/exit, per-CPU isolation | §4.1, §4.2 |
| REQ-SYNC-001, REQ-SYNC-002 | Blocking synchronization at PASSIVE_LEVEL | §4.8 |
| REQ-TS-002 | Per-CPU state is cache-line aligned | §4.1 |
| REQ-WI-001..REQ-WI-008 | Work item allocation, scheduling, cancellation | §4.7 |
| REQ-LIFE-005, REQ-LIFE-006 | Orderly shutdown with rundown protection | §4.9 |
| REQ-ECS-004 | Cross-CPU thread migration handling | §4.2 |
| REQ-COMP-001..REQ-COMP-008 | Three-phase epoch computation protocol | §4.4 |

## 3. Architecture

### 3.1 Component Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              Global State                                    │
│                                                                              │
│  _ebpf_epoch_published_current_epoch (volatile int64_t, starts at 1)         │
│  _ebpf_epoch_compute_release_epoch_timer (KTIMER)                            │
│  _ebpf_epoch_timer_dpc (KDPC, targeted to CPU 0)                             │
│  _ebpf_epoch_compute_release_epoch_message (static message)                  │
│  _ebpf_epoch_work_item_rundown_ref (rundown reference)                       │
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
  ┌──────▼──────┐           ┌───────▼──────┐          ┌───────▼──────┐
  │   CPU 0     │   DPC     │   CPU 1      │   DPC    │   CPU N-1    │
  │             │  message  │              │ message  │              │
  │ epoch_state │◄─────────►│ epoch_state  │◄────────►│ epoch_state  │
  │   _list     │           │   _list      │          │   _list      │
  │ free_list   │           │ free_list    │          │ free_list    │
  │ current_ep  │           │ current_ep   │          │ current_ep   │
  │ released_ep │           │ released_ep  │          │ released_ep  │
  │ work_queue  │           │ work_queue   │          │ work_queue   │
  │ [flags]     │           │ [flags]      │          │ [flags]      │
  └─────────────┘           └──────────────┘          └──────────────┘

  Each per-CPU entry is cache-line aligned (EBPF_CACHE_LINE_SIZE).
  Access is restricted to the owning CPU at IRQL >= DISPATCH_LEVEL.
```

**[High]** (`ebpf_epoch.c:54-70`, `ebpf_epoch.c:75-80`, `ebpf_epoch.c:160-170`)

### 3.2 Data Flow

```
  Caller                  Per-CPU State                Timer / DPC
  ──────                  ─────────────                ───────────
     │                         │                            │
     │ ebpf_epoch_enter()      │                            │
     ├────────────────────────►│ Insert into                │
     │  stamp epoch from       │ epoch_state_list           │
     │  published_epoch        │                            │
     │                         │                            │
     │ ... use protected       │                            │
     │     memory ...          │                            │
     │                         │                            │
     │ ebpf_epoch_free()       │                            │
     ├────────────────────────►│ Stamp freed_epoch,         │
     │                         │ insert into free_list      │
     │                         │ arm timer if needed ──────►│
     │                         │                            │
     │ ebpf_epoch_exit()       │                            │
     ├────────────────────────►│ Remove from                │
     │                         │ epoch_state_list           │
     │                         │ flush work queue           │
     │                         │                            │
     │                         │        Timer fires (1 ms)  │
     │                         │◄───────────────────────────┤
     │                         │                            │
     │                         │  PROPOSE → CPU 0..N-1      │
     │                         │  (compute min epoch)       │
     │                         │                            │
     │                         │  COMMIT  → CPU 0..N-1      │
     │                         │  (release eligible items)  │
     │                         │                            │
     │                         │  COMPLETE → CPU 0          │
     │                         │  (clear in_progress flag)  │
     │                         │                            │
```

**[High]** (`ebpf_epoch.c:357-423`, `ebpf_epoch.c:672-713`, `ebpf_epoch.c:728-753`,
`ebpf_epoch.c:776-888`)

### 3.3 State Model

Each per-CPU entry (`ebpf_epoch_cpu_entry_t`) maintains three boolean flags
as bit-fields: **[High]** (`ebpf_epoch.c:66-68`)

| Flag | Purpose | Set When | Cleared When |
|------|---------|----------|--------------|
| `timer_armed` | Prevents redundant timer arming | `_ebpf_epoch_arm_timer_if_needed` arms the timer (`ebpf_epoch.c:652`) | COMMIT phase clears it (`ebpf_epoch.c:847`) |
| `rundown_in_progress` | Blocks timer arming and message processing during shutdown | RUNDOWN message received (`ebpf_epoch.c:927`) | Never cleared (terminal state) |
| `epoch_computation_in_progress` | Prevents overlapping epoch computations | Timer DPC initiates PROPOSE (`ebpf_epoch.c:741`) | COMPLETE message received on CPU 0 (`ebpf_epoch.c:883`) |

**State transitions:**

```
                    ┌──────────┐
                    │  IDLE    │ timer_armed=0, epoch_computation_in_progress=0
                    └────┬─────┘
                         │ free list non-empty → arm timer
                         ▼
                    ┌──────────┐
                    │  ARMED   │ timer_armed=1
                    └────┬─────┘
                         │ timer fires
                         ▼
                    ┌──────────┐
                    │ COMPUTING│ epoch_computation_in_progress=1
                    └────┬─────┘
                         │ COMMIT clears timer_armed (per-CPU)
                         │ COMPLETE clears epoch_computation_in_progress (CPU 0)
                         ▼
                    ┌──────────┐
                    │  IDLE    │ (may re-arm if free list non-empty)
                    └──────────┘

  RUNDOWN_IN_PROGRESS → terminal; all other transitions blocked.
```

## 4. Detailed Design

### 4.1 Per-CPU State Management

**`ebpf_epoch_cpu_entry_t`** (`ebpf_epoch.c:60-70`): **[High]**

```c
typedef __declspec(align(EBPF_CACHE_LINE_SIZE)) struct _ebpf_epoch_cpu_entry
{
    LIST_ENTRY epoch_state_list;           // Active reader list
    ebpf_list_entry_t free_list;           // Deferred-free queue
    int64_t current_epoch;                 // Local epoch cache
    int64_t released_epoch;                // Reclamation threshold
    int timer_armed : 1;
    int rundown_in_progress : 1;
    int epoch_computation_in_progress : 1;
    ebpf_timed_work_queue_t* work_queue;   // Inter-CPU message queue
} ebpf_epoch_cpu_entry_t;
```

**Key design choices:**

- **Cache-line alignment** (`__declspec(align(EBPF_CACHE_LINE_SIZE))`): eliminates
  false-sharing between CPUs. A `static_assert` verifies the allocation header
  fits within one cache line (`ebpf_epoch.c:196-197`). **[High]**
- **No locks**: all access occurs at `IRQL >= DISPATCH_LEVEL`, pinning the
  thread to the owning CPU. This invariant replaces locking. **[High]**
  (`ebpf_epoch.c:56-58`)
- **Allocated once** at `ebpf_epoch_initiate()` as a contiguous, cache-aligned
  array sized to `ebpf_get_cpu_count()` (`ebpf_epoch.c:259-266`). **[High]**

**Global state** (`ebpf_epoch.c:15, 75, 80, 160, 165, 170, 221`):

| Variable | Type | Purpose |
|----------|------|---------|
| `_ebpf_epoch_published_current_epoch` | `volatile int64_t` (init 1) | Single source of truth for reader and retirement stamping |
| `_ebpf_epoch_cpu_table` | `ebpf_epoch_cpu_entry_t*` | Array of per-CPU entries |
| `_ebpf_epoch_cpu_count` | `uint32_t` | CPU count frozen at init |
| `_ebpf_epoch_compute_release_epoch_timer` | `KTIMER` | Periodic epoch-computation trigger |
| `_ebpf_epoch_timer_dpc` | `KDPC` | DPC targeted to CPU 0 |
| `_ebpf_epoch_compute_release_epoch_message` | `ebpf_epoch_cpu_message_t` | Reusable message for timer-initiated cycles |
| `_ebpf_epoch_work_item_rundown_ref` | `cxplat_rundown_reference_t` | Tracks outstanding work-item callbacks |

### 4.2 Epoch Enter/Exit

#### `ebpf_epoch_enter()` (`ebpf_epoch.c:357-368`) **[High]**

```
1. Raise IRQL to DISPATCH_LEVEL (if below).
2. Record cpu_id = current CPU.
3. Stamp epoch = ReadAcquire64(&_ebpf_epoch_published_current_epoch).
4. Insert epoch_state into per-CPU epoch_state_list (tail).
5. Lower IRQL back to original.
```

The `ReadAcquire64` forms a release/acquire pair with the
`InterlockedIncrement` performed by the PROPOSE phase on CPU 0, ensuring
ordering without a `LOCK`-prefixed instruction on the reader path
(`ebpf_epoch.c:20-25`). **[High]**

#### `ebpf_epoch_exit()` (`ebpf_epoch.c:375-423`) **[High]**

```
1. Raise IRQL to DISPATCH_LEVEL.
2. Assert IRQL matches irql_at_enter (consistency check).
3. If current CPU ≠ epoch_state->cpu_id:
   a. FAIL_FAST if irql_at_enter was DISPATCH_LEVEL (impossible migration).
   b. Lower IRQL.
   c. Send EXIT_EPOCH message to original CPU, wait for completion.
   d. Return.
4. Remove epoch_state from epoch_state_list.
5. Arm timer if free list is non-empty.
6. Flush work queue if non-empty.
7. Lower IRQL.
```

The cross-CPU exit path (`ebpf_epoch.c:386-412`) handles thread migration
that can occur when a thread entered epoch at `IRQL < DISPATCH_LEVEL`, was
preempted, and resumed on a different CPU. The exit must still remove
`epoch_state` from the **original** CPU's list. **[High]**

### 4.3 Memory Allocation and Deferred Free

#### Allocation

Two allocation variants prepend a header before the user-visible pointer:

| Function | Header Layout | Source |
|----------|--------------|--------|
| `ebpf_epoch_allocate_with_tag` | `[header][user data]` — header at `(ptr - sizeof(header))` | `ebpf_epoch.c:426-439` |
| `ebpf_epoch_allocate_cache_aligned_with_tag` | `[header at +0][padding][user data at +CACHE_LINE_SIZE]` | `ebpf_epoch.c:447-460` |

**Header structure** (`ebpf_epoch.c:189-194`): **[High]**

```c
typedef struct _ebpf_epoch_allocation_header {
    ebpf_list_entry_t list_entry;
    int64_t freed_epoch;
    ebpf_epoch_allocation_type_t entry_type;
} ebpf_epoch_allocation_header_t;
```

#### Deferred Free — `_ebpf_epoch_insert_in_free_list()` (`ebpf_epoch.c:672-713`) **[High]**

```
1. Raise IRQL to DISPATCH_LEVEL.
2. Get current CPU entry.
3. If rundown_in_progress:
   a. Immediately release/execute the item (type-dispatched).
   b. Return.
4. Stamp freed_epoch = max(published_epoch, local_epoch).
   - Uses the globally published epoch to prevent epoch-skew hazards.
5. Insert into per-CPU free_list (tail).
6. Arm timer if needed.
7. Lower IRQL.
```

**Double-free detection**: `ebpf_epoch_free()` checks `header->freed_epoch == 0`
and triggers `FAST_FAIL_HEAP_METADATA_CORRUPTION` if violated
(`ebpf_epoch.c:474`). **[High]**

### 4.4 Epoch Computation Protocol

The protocol is a 3-phase, sequential, ring-based computation driven by inter-CPU
DPC messages. It is serialized: at most one computation is in flight at a time,
guarded by `epoch_computation_in_progress`. **[High]**

#### Message types (`ebpf_epoch.c:85-120`)

| Enum Value | Phase | Direction |
|------------|-------|-----------|
| `PROPOSE_RELEASE_EPOCH` | 1 | CPU 0 → 1 → ... → N-1 |
| `COMMIT_RELEASE_EPOCH` | 2 | CPU 0 → 1 → ... → N-1 |
| `PROPOSE_EPOCH_COMPLETE` | 3 | CPU (N-1) → CPU 0 |

#### Phase 1 — PROPOSE (`ebpf_epoch.c:776-823`) **[High]**

```
CPU 0:
  new_epoch = InterlockedIncrement(&_ebpf_epoch_published_current_epoch)
  cpu_entry->current_epoch = new_epoch
  message.proposed_release_epoch = new_epoch

Each CPU (including 0):
  if cpu != 0: cpu_entry->current_epoch = message.current_epoch
  MemoryBarrier()
  minimum = message.proposed_release_epoch
  for each epoch_state in epoch_state_list:
      minimum = min(minimum, epoch_state->epoch)
  message.proposed_release_epoch = minimum

Last CPU (N-1):
  Convert message type to COMMIT_RELEASE_EPOCH
  message.released_epoch = minimum
  Send to CPU 0
```

The `MemoryBarrier()` after updating `current_epoch` ensures stores
are visible before scanning the epoch state list (`ebpf_epoch.c:798`). **[Medium]**

#### Phase 2 — COMMIT (`ebpf_epoch.c:841-863`) **[High]**

```
Each CPU (0 → 1 → ... → N-1):
  cpu_entry->timer_armed = false
  cpu_entry->released_epoch = message.released_epoch - 1
  Send message to next CPU (or COMPLETE to CPU 0 if last)
  _ebpf_epoch_release_free_list(cpu_entry, cpu_entry->released_epoch)
```

Note: the `released_epoch` is set to `committed - 1` because the current epoch
is the one just declared; items stamped with it may still have active readers.

#### Phase 3 — COMPLETE (`ebpf_epoch.c:876-888`) **[High]**

```
CPU 0:
  If message is the timer's static message:
    cpu_entry->epoch_computation_in_progress = false
  Else (ad-hoc from ebpf_epoch_synchronize):
    KeSetEvent(&message->completion_event)
```

### 4.5 Free List Release

`_ebpf_epoch_release_free_list()` (`ebpf_epoch.c:589-631`) **[High]**

```
while free_list is not empty:
    entry = head of free_list
    header = CONTAINING_RECORD(entry, ..., list_entry)
    if header->freed_epoch <= released_epoch:
        remove entry from list
        PrefetchForWrite(entry->Flink->Flink)   // prefetch hint
        switch (header->entry_type):
            MEMORY            → ebpf_free(header)
            WORK_ITEM         → cxplat_queue_preemptible_work_item(...)
            SYNCHRONIZATION   → KeSetEvent(&sync->event)
            CACHE_ALIGNED     → ebpf_free_cache_aligned(header)
            default           → FAST_FAIL_CORRUPT_LIST_ENTRY
    else:
        break   // list is ordered by freed_epoch
arm timer if needed
```

**Ordering invariant**: items are inserted at the tail and scanned from the
head. Because epochs are monotonically non-decreasing, the list is naturally
sorted. The release loop breaks on the first ineligible item. **[High]**

### 4.6 Timer and DPC

**Timer configuration** (`ebpf_epoch.c:294-297`): **[High]**

- `KDPC` initialized with `KeInitializeDpc`, targeted to CPU 0 via
  `KeSetTargetProcessorDpc(&_ebpf_epoch_timer_dpc, 0)`.
- `KTIMER` initialized with `KeInitializeTimer`.
- Delay: 1 ms (`EBPF_EPOCH_FLUSH_DELAY_IN_NANOSECONDS = 1,000,000`,
  `ebpf_epoch.c:46`).
- Relative due time (negative value in 100-ns units): `-(1,000,000 / EBPF_NS_PER_FILETIME)`.

**Arming logic** — `_ebpf_epoch_arm_timer_if_needed()` (`ebpf_epoch.c:641-657`):
**[High]**

```
if rundown_in_progress → return
if timer_armed → return
if free_list is empty → return
timer_armed = true
KeSetTimer(timer, due_time, dpc)
```

**Timer DPC callback** — `_ebpf_epoch_timer_worker()` (`ebpf_epoch.c:728-753`):
**[High]**

```
if rundown_in_progress → return
if NOT epoch_computation_in_progress:
    epoch_computation_in_progress = true
    skipped_timers = 0
    Initialize PROPOSE message
    Send async to CPU 0
else:
    skipped_timers++
    Re-arm timer (try again later)
```

The `_ebpf_epoch_skipped_timers` counter (`ebpf_epoch.c:716`) is a diagnostic
variable tracking how many timer expirations were deferred due to an in-progress
computation. **[Medium]**

### 4.7 Work Items

**Lifecycle** (`ebpf_epoch.c:498-547`, `ebpf_epoch.c:1050-1061`): **[High]**

```
  Allocate                   Schedule                  Release
  ────────                   ────────                  ───────
  ebpf_epoch_allocate_       ebpf_epoch_schedule_      (during COMMIT phase)
    work_item()                work_item()              cxplat_queue_
  ┌─────────────┐           ┌─────────────┐              preemptible_
  │ Alloc memory│──────────►│ Insert into │              work_item()
  │ Alloc       │           │ free list   │           ┌─────────────┐
  │  preemptible│           └─────────────┘           │ Callback    │
  │  work item  │                                     │ runs outside│
  │ Acquire     │            Cancel                   │ epoch       │
  │  rundown    │           ┌─────────────┐           │             │
  │  protection │◄──────────│ Free memory │           │ Free work   │
  └─────────────┘           │ Free work   │           │ item memory │
                            │  item       │           │ Release     │
                            │ Release     │           │  rundown    │
                            │  rundown    │           └─────────────┘
                            └─────────────┘
```

**Rundown protection**: each work-item allocation acquires a rundown reference
(`ebpf_epoch.c:510`); the callback releases it (`ebpf_epoch.c:1060`). Shutdown
waits for all outstanding references before freeing the CPU table
(`ebpf_epoch.c:343`). **[High]**

**Important**: Work-item callbacks execute **outside** any epoch. If the callback
needs to access epoch-protected data, it must explicitly call `ebpf_epoch_enter()`
/ `ebpf_epoch_exit()` (`docs/EpochBasedMemoryManagement.md:173-178`). **[High]**

### 4.8 Synchronization (`ebpf_epoch_synchronize`)

`ebpf_epoch_synchronize()` (`ebpf_epoch.c:549-569`) **[High]**

```
1. Allocate ebpf_epoch_synchronization_t on the stack.
   - Contains header + KEVENT.
2. Initialize KEVENT (NotificationEvent, non-signaled).
3. Insert synchronization entry into free list
   (stamped with current freed_epoch).
4. Construct PROPOSE_RELEASE_EPOCH message (ad-hoc).
5. Send message synchronously to CPU 0
   (_ebpf_epoch_send_message_and_wait).
6. KeWaitForSingleObject on the KEVENT.
   - Blocks until the COMMIT phase releases
     the synchronization entry and signals the event.
```

**IRQL requirement**: `_IRQL_requires_max_(PASSIVE_LEVEL)` because the function
blocks (`ebpf_epoch.h:95`). **[High]**

**Stack allocation**: the synchronization entry is stack-allocated to avoid
out-of-memory failures during synchronization (`ebpf_epoch.c:555-556`). **[High]**

### 4.9 Shutdown and Rundown

`ebpf_epoch_terminate()` (`ebpf_epoch.c:313-351`) **[High]**

```
1. Guard: if _ebpf_epoch_cpu_table is NULL → return.
2. Send RUNDOWN_IN_PROGRESS message to CPU 0 (synchronous, forwarded to all CPUs).
   - Each CPU sets rundown_in_progress = true.
   - Last CPU signals completion event.
3. KeCancelTimer — cancel the epoch computation timer.
4. KeFlushQueuedDpcs — wait for any active DPC to complete.
5. For each CPU:
   a. _ebpf_epoch_release_free_list(cpu_entry, MAXINT64) — force-release all items.
   b. Assert free list is empty.
   c. ebpf_timed_work_queue_destroy(cpu_entry->work_queue).
6. cxplat_wait_for_rundown_protection_release — wait for all
   outstanding work-item callbacks to complete.
7. _ebpf_epoch_cpu_count = 0.
8. Free _ebpf_epoch_cpu_table (cache-aligned free).
9. Set _ebpf_epoch_cpu_table = NULL.
```

**Ordering rationale**: rundown messages are sent first (step 2) so that any
concurrent `_ebpf_epoch_insert_in_free_list` calls during steps 3-5 execute
their items immediately instead of queuing them. **[High]**

### 4.10 Epoch Skew Protection

**Problem**: In a naïve per-CPU epoch design, CPU A might advance the epoch to
N+1 and hand that value to a reader, while CPU B (which has not yet processed
the advance message) stamps a retirement with epoch N. The retirement at N
would be reclaimed as soon as epoch N is released, but the reader at N+1 might
still reference the same data structure (if it was visible before the epoch
advanced). **[High]** (`ebpf_epoch.c:8-14`)

**Solution**: A single global variable `_ebpf_epoch_published_current_epoch`
serves as the source of truth for **both** reader stamping
(`ebpf_epoch_enter`) and retirement stamping (`_ebpf_epoch_insert_in_free_list`).

- **Reader side**: `ReadAcquire64` (acquire fence) — lightweight, no
  bus-locked instruction (`ebpf_epoch.c:20-25`).
- **Writer side**: `InterlockedIncrement` (release semantics) during PROPOSE
  on CPU 0 (`ebpf_epoch.c:787`).
- **Retirement side**: `freed_epoch = max(published_epoch, local_epoch)` —
  ensures the stamp is never lower than what a concurrent reader might observe
  (`ebpf_epoch.c:702-706`). **[High]**

This design ensures:
1. A retirement's `freed_epoch` is always ≥ the epoch of any reader that could
   see the retired data.
2. The `released_epoch` (set to `proposed - 1`) never releases items
   concurrently visible to any active reader.

## 5. Tradeoff Analysis

| Decision | Alternative Considered | Rationale |
|----------|----------------------|-----------|
| **Per-CPU state (no global lock)** | Global lock on epoch state | Per-CPU avoids lock contention on the hot path (enter/exit). Cost: complexity in cross-CPU exit and 3-phase messaging. **[High]** |
| **DPC-based inter-CPU messaging** | Inter-Processor Interrupt (IPI) | DPCs can be batched and are less disruptive than IPIs. The timed work queue provides natural batching under load. Cost: higher latency for reclamation (~1 ms minimum). **[Medium]** |
| **Timer-driven computation (1 ms)** | Immediate computation on each free | Timer batches multiple frees into a single epoch computation cycle. Under load, this amortizes the O(N-CPUs) cost of the propose/commit sweep. Cost: items linger in free lists for up to 1 ms. **[High]** |
| **Global published epoch** | Per-CPU epoch advancement | A single global variable eliminates epoch-skew hazards (§4.10) and is simpler to reason about. Cost: a single `InterlockedIncrement` per cycle, plus `ReadAcquire64` per enter/retire. **[High]** |
| **Sequential ring message passing** | Broadcast (fan-out/fan-in) | Sequential passing avoids message storms and ensures a single reducer computes the minimum. Cost: latency scales linearly with CPU count. **[Medium]** (`docs/EpochBasedMemoryManagement.md:182-184`) |
| **Stack-allocated synchronization** | Heap-allocated | Stack allocation avoids OOM during `ebpf_epoch_synchronize`. Cost: caller must block (cannot be used at `DISPATCH_LEVEL`). **[High]** |
| **`released_epoch = proposed - 1`** | `released_epoch = proposed` | Subtracting 1 provides a safety margin: items stamped with the epoch that was just declared are not released until the next cycle, ensuring no reader at the current epoch is affected. **[High]** |

## 6. Security Considerations

| Concern | Mitigation | Source |
|---------|-----------|--------|
| **Double-free detection** | `ebpf_epoch_free` checks `freed_epoch == 0` before insertion. A non-zero value indicates the header was already queued. Triggers `FAST_FAIL_HEAP_METADATA_CORRUPTION`. | `ebpf_epoch.c:474`, `ebpf_epoch.c:492` |
| **Pool corruption detection** | `_ebpf_epoch_release_free_list` defaults to `FAST_FAIL_CORRUPT_LIST_ENTRY` for unknown `entry_type` values. | `ebpf_epoch.c:620-622` |
| **IRQL enforcement** | Cross-CPU exit at `DISPATCH_LEVEL` is a `FAST_FAIL_INVALID_ARG` because thread migration at dispatch is architecturally impossible and indicates corruption. | `ebpf_epoch.c:389` |
| **Invalid message type** | The messenger worker asserts and returns if `message_type` is out of bounds for the handler array. | `ebpf_epoch.c:993-996` |
| **Rundown safety** | Work items acquire rundown protection at allocation; callbacks release it. Shutdown waits for all outstanding references before tearing down state. | `ebpf_epoch.c:510`, `ebpf_epoch.c:1060`, `ebpf_epoch.c:343` |
| **Stack-based synchronization lifetime** | `ebpf_epoch_synchronize` blocks until the synchronization entry is signaled, ensuring the stack frame remains valid while the entry is on the free list. | `ebpf_epoch.c:555-568` |

## 7. Operational Considerations

| Topic | Details |
|-------|---------|
| **Timer tuning** | The 1 ms flush delay (`EBPF_EPOCH_FLUSH_DELAY_IN_NANOSECONDS = 1,000,000`) controls the maximum latency before reclamation begins. Lowering it reduces memory pressure but increases CPU overhead from more frequent epoch computations. The value is compile-time only (`ebpf_epoch.c:46`). **[High]** |
| **CPU count dependency** | The propose/commit cycle visits every CPU sequentially. On systems with many CPUs, each cycle's latency scales linearly. The `_ebpf_epoch_skipped_timers` diagnostic counter (`ebpf_epoch.c:716`) can indicate if cycles are overlapping. **[Medium]** |
| **Stale item draining** | Items remain on free lists until an epoch computation runs and the released_epoch advances past their `freed_epoch`. If no threads enter/exit epochs (low activity), the timer backstop ensures items are eventually drained. **[High]** |
| **Work queue flush on exit** | `ebpf_epoch_exit` opportunistically flushes the per-CPU work queue (`ebpf_epoch.c:418-420`), providing prompt processing at correctness boundaries without waiting for the timer. **[Medium]** |
| **Diagnostics** | `ebpf_epoch_is_free_list_empty(cpu_id)` (`ebpf_epoch.c:571-582`) allows querying per-CPU free list state via inter-CPU messaging. The `_ebpf_epoch_skipped_timers` counter is available for debugging overlapping computations. **[Medium]** |
| **Extension API surface** | Epoch allocation/free/enter/exit are exposed to kernel extensions via the client dispatch table in `ebpf_extension.h:334-368`. Extensions allocating epoch-managed memory for custom maps must follow the same enter/exit discipline. **[High]** |

## 8. Open Questions

| # | Question | Context |
|---|----------|---------|
| 1 | **Scalability of sequential ring messaging**: As CPU count increases, the O(N) per-cycle latency may become a bottleneck. The design document notes this as a future investigation area (`docs/EpochBasedMemoryManagement.md:182-184`). Has any threshold been identified? | **[Medium]** |
| 2 | **`_ebpf_epoch_skipped_timers` observability**: This counter is a static variable with no tracepoint or ETW event. Is there a plan to expose it through a diagnostic interface? | **[Low]** |
| 3 | **Free list ordering guarantee**: The release algorithm assumes items are ordered by `freed_epoch` (breaks on first ineligible). If `max(published, local)` can produce non-monotonic values across insertions on the same CPU (e.g., local_epoch temporarily ahead due to an in-flight PROPOSE), out-of-order items would be stranded. Is this scenario possible? | **[Medium]** |
| 4 | **Timer coalescing under load**: When `epoch_computation_in_progress` is true and the timer fires again, it re-arms with the same 1 ms delay. Under sustained load, this could lead to repeated re-arms before the cycle completes. Is adaptive backoff desirable? | **[Low]** |
| 5 | **`EBPF_WORK_QUEUE_WAKEUP_ON_TIMER` vs `WAKEUP_ON_INSERT`**: The timer-initiated PROPOSE uses `WAKEUP_ON_TIMER` while ad-hoc messages use `WAKEUP_ON_INSERT`. The behavioral difference is defined in `ebpf_work_queue.h` but the tradeoffs are not documented in the epoch module. | **[Low]** |

## 9. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-30 | Copilot (spec-extraction) | Initial extraction from codebase. Sources: `libs/runtime/ebpf_epoch.c`, `libs/runtime/ebpf_epoch.h`, `include/ebpf_extension.h`, `docs/EpochBasedMemoryManagement.md`. |
