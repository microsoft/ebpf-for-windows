# Epoch Subsystem Design

## 1. Overview
- [KNOWN] The epoch subsystem is a per-CPU reclamation design that trades central locking for per-CPU participant lists, per-CPU free lists, and inter-CPU coordination. Evidence: `libs/runtime/ebpf_epoch.c:56-80`, `docs/EpochBasedMemoryManagement.md:21-27,36-53`.
- [KNOWN] Its design goal is to let readers access epoch-managed objects without taking object-level reclamation locks while deferring reclamation until all relevant readers have advanced. Evidence: `docs/EpochBasedMemoryManagement.md:5-16,28-33`, `libs/runtime/unit/platform_unit_test.cpp:743-977,994-1244`.

## 2. Requirements Summary
- [KNOWN] The design implements lifecycle, entry/exit tracking, deferred reclamation, synchronization, deferred work items, and extension-facing epoch services. Evidence: `libs/runtime/ebpf_epoch.h:23-136`, `include/ebpf_extension.h:455-489`.
- [INFERRED] The most correctness-sensitive property is that readers observe a published epoch value that is never older than retirements stamped concurrently on another CPU. Reasoning: the published epoch exists specifically to prevent newer-reader / older-retirement skew. Evidence: `libs/runtime/ebpf_epoch.c:8-15,708-713,791-800`, `libs/runtime/unit/platform_unit_test.cpp:743-977`.

## 3. Architecture
- [KNOWN] **Component 1 — Public API surface**: `ebpf_epoch.h` exposes lifecycle, read-side, memory, synchronization, work-item, and diagnostic APIs. Evidence: `libs/runtime/ebpf_epoch.h:23-136`.
- [KNOWN] **Component 2 — Per-CPU state table**: each CPU owns an epoch-state list, free list, cached current epoch, released epoch, timer state, rundown state, and timed work queue. Evidence: `libs/runtime/ebpf_epoch.c:60-80`.
- [KNOWN] **Component 3 — Global epoch publication**: a single published epoch is read on entry and retirement, and advanced during the propose phase on CPU 0. Evidence: `libs/runtime/ebpf_epoch.c:8-25,791-800`.
- [KNOWN] **Component 4 — Inter-CPU messenger**: timed work queues carry propose, commit, completion, cross-CPU-exit, rundown, and free-list-query messages. Evidence: `libs/runtime/ebpf_epoch.c:85-155,968-1048`.
- [KNOWN] **Component 5 — Reclamation executor**: `_ebpf_epoch_release_free_list` either frees memory, frees cache-aligned memory, signals synchronization events, or queues preemptible work items. Evidence: `libs/runtime/ebpf_epoch.c:595-637`.
- [KNOWN] **Boundary**: extension map providers consume a narrowed epoch contract through `ebpf_base_map_client_dispatch_table_t`. Evidence: `include/ebpf_extension.h:455-489`.

## 4. Detailed Design
- [KNOWN] **Entry/exit path**: `ebpf_epoch_enter` raises IRQL if needed, captures CPU and published epoch, links the state into the current CPU list, then restores IRQL; `ebpf_epoch_exit` removes the state, arms reclamation if needed, and opportunistically flushes the CPU work queue. The extension-facing epoch contract treats these operations as re-entrant when callers use properly paired state objects for nested entry/exit scopes. Evidence: `libs/runtime/ebpf_epoch.c:357-423`, `include/ebpf_extension.h:459-462`.
- [KNOWN] **Cross-CPU exit path**: if the current CPU differs from the owner CPU, exit sends `EXIT_EPOCH` to the owner CPU and lets the owner perform the actual list removal. Evidence: `libs/runtime/ebpf_epoch.c:383-411,897-916`.
- [KNOWN] **Retirement path**: epoch-managed frees and scheduled work items pass through `_ebpf_epoch_insert_in_free_list`, which stamps `freed_epoch` as `max(published_epoch, local_epoch)` before queueing to the local CPU free list. Evidence: `libs/runtime/ebpf_epoch.c:468-501,533-537,679-718`.
- [KNOWN] **Epoch computation path**: a timer DPC on CPU 0 starts a `PROPOSE_RELEASE_EPOCH` cycle, CPU 0 increments the published epoch, each CPU folds its local minimum reader epoch into the proposal, and a commit pass sets `released_epoch = proposed_release_epoch - 1` on every CPU before reclamation. Evidence: `libs/runtime/ebpf_epoch.c:734-759,782-868`, `docs/EpochBasedMemoryManagement.md:106-151`.
- [KNOWN] **Synchronization path**: `ebpf_epoch_synchronize` inserts a stack-allocated synchronization record into epoch retirement state, forces a propose cycle, and waits until reclamation signals the event. Evidence: `libs/runtime/ebpf_epoch.c:555-575`.
- [KNOWN] **Work-item path**: allocating a work item acquires rundown protection and creates a preemptible worker wrapper; when reclamation makes the item eligible, the subsystem queues the worker, which invokes the callback and releases rundown protection. Callbacks run outside any epoch by default, so callbacks that need epoch-managed access must explicitly enter and exit an epoch. Evidence: `libs/runtime/ebpf_epoch.c:504-553,612-615,1056-1067`, `docs/EpochBasedMemoryManagement.md:173-178`.
- [KNOWN] **Shutdown path**: termination first broadcasts rundown-in-progress, cancels the timer, flushes DPCs, drains all free lists with `MAXINT64`, destroys work queues, then waits for outstanding work items. Evidence: `libs/runtime/ebpf_epoch.c:313-350`.

## 5. Tradeoff Analysis
- [KNOWN] **Per-CPU lists instead of a global reader registry** reduce lock contention on hot paths but require inter-CPU coordination to compute a safe release epoch. Evidence: `docs/EpochBasedMemoryManagement.md:21-27,106-151`.
- [KNOWN] **Timer-driven batching plus exit-driven flushing** balances background amortization against prompt handling at correctness boundaries. Evidence: `docs/EpochBasedMemoryManagement.md:81-93`, `libs/runtime/ebpf_epoch.c:417-420,647-661,734-759`.
- [INFERRED] **Published-epoch stamping** is an intentional correctness-over-simplicity choice introduced to prevent reclamation skew; a simpler local-epoch-only stamp would be cheaper but unsafe. Evidence: `libs/runtime/ebpf_epoch.c:8-15,708-713`; regression intent in `libs/runtime/unit/platform_unit_test.cpp:743-748`.

## 6. Security Considerations
- [KNOWN] The subsystem sits on a kernel correctness boundary because premature reclamation can become a use-after-free in privileged code. Evidence: `libs/runtime/unit/platform_unit_test.cpp:989-993,1071-1080`.
- [KNOWN] Extension-facing documentation states that calling epoch memory operations outside an epoch-protected region can lead to undefined behavior. Evidence: `include/ebpf_extension.h:469-477`, `docs/CustomMaps.md:302-305`.
- [KNOWN] Several invariant violations are fail-fast conditions, including invalid cross-CPU exit at dispatch and detected pool metadata corruption/double free. Evidence: `libs/runtime/ebpf_epoch.c:48-52,389-390,479-480,497-498,627-628`.

## 7. Operational Considerations
- [KNOWN] Correctness depends on CPU affinity behavior, IRQL transitions, timers, DPC processing, and per-CPU work queues. Evidence: `libs/runtime/ebpf_epoch.c:281-297,357-423,734-759`.
- [KNOWN] The test suite uses explicit CPU affinity, long-running stress, and forced synchronization to surface timing-sensitive reclamation bugs. Evidence: `libs/runtime/unit/platform_unit_test.cpp:704-724,762-977,995-1244`.
- [KNOWN] Performance tests measure epoch entry/exit and entry/allocate/free/exit paths but do not define thresholds in the scoped sources. Evidence: `tests/performance/platform.cpp:8-31`.

## 8. Open Questions
- [KNOWN] None identified.

## 9. Revision History
- [KNOWN] Version 0.2 — 2026-06-30 — Reissued with explicit nested entry/exit and callback-context design constraints.
