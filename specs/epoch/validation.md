<!-- Copyright (c) eBPF for Windows contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Epoch Module — Validation Plan

## 1. Overview

### 1.1 Objectives

This document defines the validation plan for the `ebpf_epoch` module, the epoch-based
memory reclamation (EBR) subsystem of eBPF for Windows. The objectives are:

1. Verify that all public API functions behave according to their documented contracts.
2. Verify that epoch-protected memory is never reclaimed while any thread holds an epoch
   reference to it (the core safety invariant).
3. Verify correct behavior under concurrent, multi-CPU workloads.
4. Identify coverage gaps and propose additional test cases to close them.

### 1.2 System Under Test

The system under test comprises two source files:

| File | Purpose |
|------|---------|
| `libs/runtime/ebpf_epoch.h` | Public API (13 functions, 2 types) |
| `libs/runtime/ebpf_epoch.c` | Implementation (~1060 lines) |

The module provides:

- **Epoch critical sections** — `ebpf_epoch_enter` / `ebpf_epoch_exit` bracket access to
  epoch-protected memory.
- **Deferred-free memory management** — `ebpf_epoch_allocate*` / `ebpf_epoch_free*` defer
  reclamation until no thread references the freed epoch.
- **Epoch work items** — callbacks scheduled for execution after an epoch completes.
- **Synchronization** — `ebpf_epoch_synchronize` blocks until the current epoch ends.
- **Per-CPU free lists** with a three-phase epoch computation algorithm that propagates
  a release epoch through all CPUs via inter-CPU message passing.

### 1.3 Validation Approach

Validation combines three complementary strategies:

1. **Functional unit tests** — verify individual API contracts in single-threaded contexts.
2. **Concurrency integration tests** — verify multi-thread, multi-CPU correctness using
   CPU-affinity and signaling to create specific interleaving scenarios.
3. **Stress tests** — exercise the module under sustained concurrent load for extended
   durations to expose timing-dependent defects.

All tests execute in user mode via the **usersim** platform simulation layer, which
emulates kernel primitives (IRQL, DPC, KTIMER, KEVENT) in user space.

---

## 2. Scope of Validation

### 2.1 In Scope

- All 13 public API functions declared in `ebpf_epoch.h`.
- The `ebpf_epoch_state_t` structure lifecycle.
- Per-CPU free-list draining and the three-phase epoch computation algorithm (as
  observable through public API behavior).
- Work-item allocation, scheduling, cancellation, and callback execution.
- Thread-safety guarantees across multiple CPUs.
- Graceful initialization failure handling (EBPF_NO_MEMORY path).
- Module lifecycle (initiate / terminate), including resource cleanup.

### 2.2 Out of Scope

- Kernel-mode-only behaviors that cannot be simulated by usersim (e.g., real IRQL
  enforcement, true DPC delivery constraints).
- Performance benchmarks (covered separately in `tests/performance/platform.cpp`).
- Internal helper functions not reachable through the public API (validated indirectly).
- Integration with other eBPF subsystems (map management, program loading).

### 2.3 Constraints

| Constraint | Impact |
|------------|--------|
| Tests run in user mode via usersim | IRQL semantics are simulated, not enforced by hardware |
| Multi-CPU tests require ≥ 2 or ≥ 4 logical CPUs | Tests auto-skip on under-provisioned machines |
| Stress test duration varies by environment | 5 s local, 120 s CI-PR, 600 s CI-scheduled |
| `VirtualAlloc`/`VirtualProtect` used for UAF detection in stress tests | Windows-specific; not portable |

---

## 3. Test Strategy

### 3.1 Test Levels

| Level | Description | Examples |
|-------|-------------|----------|
| **Unit** | Single-threaded tests of individual API functions | TC-LIFE-001, TC-MEM-001 |
| **Integration** | Multi-threaded tests verifying cross-CPU epoch behavior | TC-TS-001, TC-COMP-001 |
| **Stress** | Long-running concurrent tests seeking timing-dependent defects | TC-ROB-001, TC-ROB-002 |

### 3.2 Test Techniques

| Technique | Purpose |
|-----------|---------|
| **Functional** | Verify API return values, pointer alignment, allocation semantics |
| **Concurrency** | CPU-affine threads with signaling to create controlled interleavings |
| **Stress / Soak** | Sustained reader/writer loops with epoch synchronization to detect UAF |
| **Fault injection** | Verify initialization failure handling (proposed — not yet implemented) |
| **Boundary** | NULL pointers, zero-size allocations, edge cases (proposed) |

### 3.3 Test Environment

| Component | Details |
|-----------|---------|
| **Platform** | Windows (x64), usersim simulation layer |
| **Framework** | Catch2 (v3) |
| **Init helper** | `_test_helper` RAII class initializes platform, random, epoch, object tracking, async, state |
| **Epoch scope** | `ebpf_epoch_scope_t` RAII wrapper for `ebpf_epoch_enter` / `ebpf_epoch_exit` |
| **Source file** | `libs/runtime/unit/platform_unit_test.cpp` |
| **Test tag** | `[platform]` |
| **CPU requirements** | Tests declare minimum CPU counts and auto-skip if unsatisfied |

---

## 4. Requirements Traceability Matrix

### 4.1 Lifecycle Requirements

| REQ-ID | Requirement Summary | TC-IDs | Coverage |
|--------|---------------------|--------|----------|
| REQ-LIFE-001 | `ebpf_epoch_initiate` allocates per-CPU tables and work queues, returns `EBPF_SUCCESS` | TC-LIFE-001 | Full |
| REQ-LIFE-002 | `ebpf_epoch_initiate` returns `EBPF_NO_MEMORY` on allocation failure | TC-LIFE-002 | None |
| REQ-LIFE-003 | `ebpf_epoch_terminate` releases all per-CPU resources and waits for outstanding work items | TC-LIFE-001 | Partial |
| REQ-LIFE-004 | `ebpf_epoch_terminate` drains free lists during rundown (items freed immediately) | TC-LIFE-003 | None |

### 4.2 Epoch Critical Section Requirements

| REQ-ID | Requirement Summary | TC-IDs | Coverage |
|--------|---------------------|--------|----------|
| REQ-ECS-001 | `ebpf_epoch_enter` records current epoch, CPU ID, and saved IRQL in `ebpf_epoch_state_t` | TC-ECS-001 | Partial |
| REQ-ECS-002 | `ebpf_epoch_exit` removes the thread from the per-CPU epoch list | TC-ECS-001 | Partial |
| REQ-ECS-003 | IRQL is preserved across an epoch enter/exit pair (`_IRQL_requires_same_`) | TC-ECS-002 | None |
| REQ-ECS-004 | Thread that migrates CPUs between enter and exit is handled via cross-CPU message | TC-ECS-003 | None |

### 4.3 Memory Management Requirements

| REQ-ID | Requirement Summary | TC-IDs | Coverage |
|--------|---------------------|--------|----------|
| REQ-MEM-001 | `ebpf_epoch_allocate` returns a valid pointer or NULL on failure | TC-MEM-001 | Full |
| REQ-MEM-002 | `ebpf_epoch_allocate_with_tag` associates a pool tag with the allocation | TC-MEM-002 | None |
| REQ-MEM-003 | `ebpf_epoch_allocate_cache_aligned_with_tag` returns a pointer aligned to `EBPF_CACHE_LINE_SIZE` | TC-MEM-003 | Full |
| REQ-MEM-004 | `ebpf_epoch_free` defers deallocation; memory is not reclaimed while any thread holds an epoch reference | TC-MEM-001, TC-ROB-001, TC-ROB-002 | Full |
| REQ-MEM-005 | `ebpf_epoch_free_cache_aligned` defers deallocation of cache-aligned memory | TC-MEM-003 | Full |
| REQ-MEM-006 | Freed memory is reclaimed only when `released_epoch >= freed_epoch` | TC-COMP-001, TC-ROB-001, TC-ROB-002 | Full |
| REQ-MEM-007 | `ebpf_epoch_free(NULL)` is a safe no-op (`_Frees_ptr_opt_`) | TC-MEM-004 | None |

### 4.4 Epoch Computation Requirements

| REQ-ID | Requirement Summary | TC-IDs | Coverage |
|--------|---------------------|--------|----------|
| REQ-COMP-001 | Three-phase computation: propose → commit → complete | TC-COMP-001, TC-ROB-001 | Partial |
| REQ-COMP-002 | Release epoch = min(all CPUs' thread epochs) − 1 | TC-COMP-002, TC-ROB-001 | Full |
| REQ-COMP-003 | Computation propagates sequentially through all CPUs via inter-CPU messages | TC-COMP-001 | Partial |
| REQ-COMP-004 | Global epoch (`_ebpf_epoch_published_current_epoch`) is incremented atomically per computation cycle | TC-COMP-001 | Partial |
| REQ-COMP-005 | Timer fires ≤ 1 ms after free-list insertion to trigger epoch computation | TC-COMP-001 | Partial |

### 4.5 Work Item Requirements

| REQ-ID | Requirement Summary | TC-IDs | Coverage |
|--------|---------------------|--------|----------|
| REQ-WI-001 | `ebpf_epoch_allocate_work_item` returns a work item or NULL | TC-WI-001, TC-ROB-002 | Full |
| REQ-WI-002 | `ebpf_epoch_schedule_work_item` queues work item for epoch-end execution | TC-WI-001, TC-ROB-002 | Full |
| REQ-WI-003 | Scheduled work items execute their callback at PASSIVE_LEVEL after the epoch completes | TC-ROB-001, TC-ROB-002 | Full |
| REQ-WI-004 | `ebpf_epoch_cancel_work_item` frees the work item without executing the callback | TC-WI-002 | None |
| REQ-WI-005 | Work-item allocation fails gracefully during module shutdown (rundown protection) | TC-WI-003 | None |

### 4.6 Synchronization Requirements

| REQ-ID | Requirement Summary | TC-IDs | Coverage |
|--------|---------------------|--------|----------|
| REQ-SYNC-001 | `ebpf_epoch_synchronize` blocks until the current epoch computation completes | TC-MEM-001, TC-MEM-003, TC-TS-001 | Full |
| REQ-SYNC-002 | `ebpf_epoch_synchronize` requires `IRQL <= PASSIVE_LEVEL` | — | None |

### 4.7 Diagnostics Requirements

| REQ-ID | Requirement Summary | TC-IDs | Coverage |
|--------|---------------------|--------|----------|
| REQ-DIAG-001 | `ebpf_epoch_is_free_list_empty` returns true when no deferred items remain on the specified CPU | TC-COMP-001 | Full |
| REQ-DIAG-002 | Skipped-timer counter tracks epoch computation contention | — | None |

### 4.8 Thread Safety Requirements

| REQ-ID | Requirement Summary | TC-IDs | Coverage |
|--------|---------------------|--------|----------|
| REQ-TS-001 | Per-CPU data is accessed only at DISPATCH_LEVEL (lock-free) | — | Partial |
| REQ-TS-002 | Concurrent epoch enter/exit across CPUs does not corrupt state | TC-TS-001, TC-ROB-002 | Full |
| REQ-TS-003 | Inter-CPU message passing serializes cross-CPU operations | TC-COMP-001, TC-COMP-002 | Partial |
| REQ-TS-004 | Memory barriers ensure epoch visibility across CPUs | TC-COMP-002, TC-ROB-002 | Partial |

### 4.9 Robustness Requirements

| REQ-ID | Requirement Summary | TC-IDs | Coverage |
|--------|---------------------|--------|----------|
| REQ-ROB-001 | No use-after-free under concurrent readers and writers | TC-ROB-002 | Full |
| REQ-ROB-002 | CPU scheduling skew does not cause premature reclamation | TC-ROB-001 | Full |
| REQ-ROB-003 | System stable under sustained multi-minute stress | TC-ROB-002 | Full |
| REQ-ROB-004 | Initialization failure cleans up partially-allocated resources (no leaks) | TC-LIFE-002 | None |

---

## 5. Test Cases

### TC-LIFE-001: Basic initialization and termination

- **ID**: TC-LIFE-001
- **Title**: Basic initialization and termination
- **Linked Requirements**: REQ-LIFE-001, REQ-LIFE-003
- **Test Level**: Unit
- **Preconditions**: Platform initialized
- **Steps**:
  1. Call `_test_helper.initialize()` (internally calls `ebpf_epoch_initiate()`).
  2. Perform a trivial epoch operation (enter → allocate → free → exit → synchronize).
  3. Destroy `_test_helper` (internally calls `ebpf_epoch_terminate()`).
- **Expected Results**: Initialization succeeds. All operations complete without error. Termination releases resources without leaks.
- **Pass/Fail Criteria**: No crash, no assertion failure, no memory leak reported by object tracking.
- **Confidence**: [High]
- **Source**: `platform_unit_test.cpp:634` (`epoch_test_single_epoch`)

---

### TC-LIFE-002: Initialization failure returns EBPF_NO_MEMORY [PROPOSED]

- **ID**: TC-LIFE-002
- **Title**: Initialization failure returns EBPF_NO_MEMORY
- **Linked Requirements**: REQ-LIFE-002, REQ-ROB-004
- **Test Level**: Unit
- **Preconditions**: Platform initialized; fault-injection framework available
- **Steps**:
  1. Enable fault injection to fail the per-CPU table allocation (`cxplat_allocate`).
  2. Call `ebpf_epoch_initiate()`.
  3. Verify return value is `EBPF_NO_MEMORY`.
  4. Verify no partial state remains (CPU table pointer is NULL).
  5. Re-enable allocation. Call `ebpf_epoch_initiate()` and verify `EBPF_SUCCESS`.
- **Expected Results**: First call returns `EBPF_NO_MEMORY`. Module is in a clean un-initialized state. Second call succeeds.
- **Pass/Fail Criteria**: Correct return code; no resource leak on failure path.
- **Confidence**: [Low]
- **Source**: [PROPOSED]

---

### TC-LIFE-003: Terminate drains free lists during rundown [PROPOSED]

- **ID**: TC-LIFE-003
- **Title**: Terminate drains free lists during rundown
- **Linked Requirements**: REQ-LIFE-004
- **Test Level**: Unit
- **Preconditions**: Epoch module initialized
- **Steps**:
  1. Enter epoch. Allocate memory. Free it. Exit epoch.
  2. Do **not** call `ebpf_epoch_synchronize()`.
  3. Verify `ebpf_epoch_is_free_list_empty(cpu_id)` is false (items pending).
  4. Call `ebpf_epoch_terminate()`.
  5. Verify no memory leak is reported by object tracking.
- **Expected Results**: Terminate drains the free list and reclaims all deferred items.
- **Pass/Fail Criteria**: Object tracking reports zero outstanding allocations.
- **Confidence**: [Low]
- **Source**: [PROPOSED]

---

### TC-ECS-001: Single-thread epoch enter and exit

- **ID**: TC-ECS-001
- **Title**: Single-thread epoch enter and exit
- **Linked Requirements**: REQ-ECS-001, REQ-ECS-002
- **Test Level**: Unit
- **Preconditions**: `_test_helper` initialized
- **Steps**:
  1. Create `ebpf_epoch_scope_t` (enters epoch automatically).
  2. Allocate 10 bytes with `ebpf_epoch_allocate(10)`.
  3. Free allocation with `ebpf_epoch_free()`.
  4. Call `epoch_scope.exit()`.
  5. Call `ebpf_epoch_synchronize()`.
- **Expected Results**: Enter populates `ebpf_epoch_state_t`. Exit removes thread from CPU list. Synchronize completes.
- **Pass/Fail Criteria**: No crash; synchronize returns.
- **Confidence**: [High]
- **Source**: `platform_unit_test.cpp:634` (`epoch_test_single_epoch`)

---

### TC-ECS-002: IRQL preserved across epoch enter/exit [PROPOSED]

- **ID**: TC-ECS-002
- **Title**: IRQL preserved across epoch enter/exit
- **Linked Requirements**: REQ-ECS-003
- **Test Level**: Unit
- **Preconditions**: `_test_helper` initialized
- **Steps**:
  1. Record current IRQL.
  2. Call `ebpf_epoch_enter()`.
  3. Verify IRQL has not changed (via `ebpf_epoch_state_t.irql_at_enter`).
  4. Call `ebpf_epoch_exit()`.
  5. Verify IRQL matches the value recorded in step 1.
- **Expected Results**: IRQL is identical before enter and after exit.
- **Pass/Fail Criteria**: IRQL values match.
- **Confidence**: [Medium]
- **Source**: [PROPOSED]

---

### TC-ECS-003: Thread migration between enter and exit [PROPOSED]

- **ID**: TC-ECS-003
- **Title**: Thread migration between enter and exit
- **Linked Requirements**: REQ-ECS-004
- **Test Level**: Integration
- **Preconditions**: `_test_helper` initialized; ≥ 2 CPUs
- **Steps**:
  1. Set thread affinity to CPU 0.
  2. Call `ebpf_epoch_enter()`. Record `epoch_state.cpu_id` (should be 0).
  3. Set thread affinity to CPU 1 (simulate migration).
  4. Allocate and free memory.
  5. Call `ebpf_epoch_exit()` (now on CPU 1, triggers cross-CPU exit message).
  6. Call `ebpf_epoch_synchronize()`.
- **Expected Results**: Exit detects CPU mismatch and sends `EXIT_EPOCH` message to the original CPU. No crash or state corruption.
- **Pass/Fail Criteria**: Synchronize completes; no assertion failure.
- **Confidence**: [Medium]
- **Source**: [PROPOSED]

---

### TC-MEM-001: Epoch allocate and deferred free

- **ID**: TC-MEM-001
- **Title**: Epoch allocate and deferred free
- **Linked Requirements**: REQ-MEM-001, REQ-MEM-004, REQ-SYNC-001
- **Test Level**: Unit
- **Preconditions**: `_test_helper` initialized
- **Steps**:
  1. Enter epoch.
  2. Call `ebpf_epoch_allocate(10)`. Verify pointer is non-NULL.
  3. Call `ebpf_epoch_free(memory)`.
  4. Exit epoch.
  5. Call `ebpf_epoch_synchronize()`.
- **Expected Results**: Allocation succeeds. Free defers reclamation. Synchronize reclaims the memory.
- **Pass/Fail Criteria**: No crash; no memory leak.
- **Confidence**: [High]
- **Source**: `platform_unit_test.cpp:634` (`epoch_test_single_epoch`)

---

### TC-MEM-002: Allocate with pool tag [PROPOSED]

- **ID**: TC-MEM-002
- **Title**: Allocate with pool tag
- **Linked Requirements**: REQ-MEM-002
- **Test Level**: Unit
- **Preconditions**: `_test_helper` initialized
- **Steps**:
  1. Enter epoch.
  2. Call `ebpf_epoch_allocate_with_tag(64, 'TEST')`.
  3. Verify returned pointer is non-NULL.
  4. Write to and read from the allocation.
  5. Free with `ebpf_epoch_free()`.
  6. Exit epoch. Synchronize.
- **Expected Results**: Allocation succeeds with the specified tag. Memory is usable and reclaimed normally.
- **Pass/Fail Criteria**: Non-NULL pointer; no crash; no leak.
- **Confidence**: [Low]
- **Source**: [PROPOSED]

---

### TC-MEM-003: Cache-aligned allocation and free

- **ID**: TC-MEM-003
- **Title**: Cache-aligned allocation and free
- **Linked Requirements**: REQ-MEM-003, REQ-MEM-005
- **Test Level**: Unit
- **Preconditions**: `_test_helper` initialized
- **Steps**:
  1. Enter epoch.
  2. Call `ebpf_epoch_allocate_cache_aligned_with_tag(10, 0)`.
  3. Verify pointer is non-NULL.
  4. `memset` the allocation to 0.
  5. Assert `memory == EBPF_CACHE_ALIGN_POINTER(memory)` (alignment check).
  6. Call `ebpf_epoch_free_cache_aligned(memory)`.
  7. Exit epoch. Synchronize.
- **Expected Results**: Pointer is aligned to cache-line boundary. Memory is usable and reclaimed.
- **Pass/Fail Criteria**: `REQUIRE(memory == EBPF_CACHE_ALIGN_POINTER(memory))`.
- **Confidence**: [High]
- **Source**: `platform_unit_test.cpp:646` (`epoch_test_single_epoch_cache_aligned`)

---

### TC-MEM-004: Free NULL is a safe no-op [PROPOSED]

- **ID**: TC-MEM-004
- **Title**: Free NULL is a safe no-op
- **Linked Requirements**: REQ-MEM-007
- **Test Level**: Unit
- **Preconditions**: `_test_helper` initialized
- **Steps**:
  1. Enter epoch.
  2. Call `ebpf_epoch_free(NULL)`.
  3. Call `ebpf_epoch_free_cache_aligned(NULL)`.
  4. Exit epoch. Synchronize.
- **Expected Results**: Both calls return without crash or side effect.
- **Pass/Fail Criteria**: No crash; no assertion failure.
- **Confidence**: [Medium]
- **Source**: [PROPOSED]

---

### TC-COMP-001: Stale items drained from per-CPU free lists

- **ID**: TC-COMP-001
- **Title**: Stale items drained from per-CPU free lists
- **Linked Requirements**: REQ-COMP-001, REQ-COMP-003, REQ-COMP-004, REQ-COMP-005, REQ-DIAG-001, REQ-MEM-006
- **Test Level**: Integration
- **Preconditions**: `_test_helper` initialized; ≥ 2 CPUs
- **Steps** (100 iterations):
  1. **Thread 1** (CPU 0): Enter epoch → allocate → signal Thread 2 → wait for Thread 2 → free → exit.
  2. **Thread 2** (CPU 1): Wait for Thread 1 → enter epoch → allocate → free → exit → signal Thread 1.
  3. Join both threads.
  4. Poll `ebpf_epoch_is_free_list_empty(0)` and `ebpf_epoch_is_free_list_empty(1)` for up to 100 ms (1 ms intervals).
  5. Assert both free lists are empty.
- **Expected Results**: Epoch timer fires and three-phase computation drains both CPUs' free lists within 100 ms.
- **Pass/Fail Criteria**: `REQUIRE(ebpf_epoch_is_free_list_empty(0))` and `REQUIRE(ebpf_epoch_is_free_list_empty(1))` after 100 iterations.
- **Confidence**: [High]
- **Source**: `platform_unit_test.cpp:690` (`epoch_test_stale_items`)

---

### TC-COMP-002: Epoch skew does not cause premature reclamation

- **ID**: TC-COMP-002
- **Title**: Epoch skew does not cause premature reclamation
- **Linked Requirements**: REQ-COMP-002, REQ-ROB-002, REQ-MEM-006, REQ-TS-003, REQ-TS-004
- **Test Level**: Integration
- **Preconditions**: `_test_helper` initialized; ≥ 4 CPUs
- **Steps** (up to 25 attempts):
  1. Allocate test memory.
  2. **Hog thread** (CPU N−1, `TIME_CRITICAL` priority): busy-loop keeping lagging CPU occupied; when signaled, retire memory and schedule epoch work item.
  3. **Reader thread** (CPU 0): wait until global epoch advances past start epoch, then enter and hold epoch while reading shared pointer.
  4. Main thread releases hog thread and waits for callback invocation (500 ms timeout).
  5. Assert `callback_invoked == true`.
  6. Assert `callback_while_reader_active == false`.
- **Expected Results**: The work-item callback fires only after the reader exits its epoch, never while the reader is active.
- **Pass/Fail Criteria**: `REQUIRE(callback_invoked)` and `REQUIRE_FALSE(callback_while_reader_active)`.
- **Confidence**: [High]
- **Source**: `platform_unit_test.cpp:749` (`epoch_test_epoch_skew_reclamation_hazard`)

---

### TC-TS-001: Two-thread concurrent epoch usage

- **ID**: TC-TS-001
- **Title**: Two-thread concurrent epoch usage
- **Linked Requirements**: REQ-TS-002, REQ-MEM-001, REQ-MEM-004, REQ-SYNC-001
- **Test Level**: Integration
- **Preconditions**: `_test_helper` initialized
- **Steps**:
  1. Spawn two threads, each executing:
     a. Enter epoch.
     b. Allocate 10 bytes.
     c. Sleep 100 ms (hold epoch active).
     d. Free allocation.
     e. Exit epoch.
     f. Synchronize.
  2. Join both threads.
- **Expected Results**: Both threads complete without deadlock, crash, or corruption.
- **Pass/Fail Criteria**: Both threads join successfully; no assertion failure.
- **Confidence**: [High]
- **Source**: `platform_unit_test.cpp:663` (`epoch_test_two_threads`)

---

### TC-WI-001: Work item allocate, schedule, and execute

- **ID**: TC-WI-001
- **Title**: Work item allocate, schedule, and execute
- **Linked Requirements**: REQ-WI-001, REQ-WI-002, REQ-WI-003
- **Test Level**: Integration
- **Preconditions**: `_test_helper` initialized; ≥ 2 CPUs
- **Steps**:
  1. Allocate a work item with `ebpf_epoch_allocate_work_item(context, callback)`.
  2. Schedule it with `ebpf_epoch_schedule_work_item(work_item)`.
  3. Call `ebpf_epoch_synchronize()` to advance the epoch.
  4. Wait for callback invocation (poll for up to 500 ms).
  5. Assert the callback was invoked with the correct context.
- **Expected Results**: Callback fires after the epoch completes, with the originally supplied context pointer.
- **Pass/Fail Criteria**: Callback invoked; context matches.
- **Confidence**: [Medium] — covered indirectly by TC-COMP-002 and TC-ROB-002; no dedicated standalone test exists.
- **Source**: Derived from `platform_unit_test.cpp:749` (work item usage in `epoch_test_epoch_skew_reclamation_hazard`)

---

### TC-WI-002: Cancel work item before execution [PROPOSED]

- **ID**: TC-WI-002
- **Title**: Cancel work item before execution
- **Linked Requirements**: REQ-WI-004
- **Test Level**: Unit
- **Preconditions**: `_test_helper` initialized
- **Steps**:
  1. Allocate a work item with `ebpf_epoch_allocate_work_item(context, callback)`.
  2. Call `ebpf_epoch_cancel_work_item(work_item)` (before scheduling).
  3. Call `ebpf_epoch_synchronize()`.
  4. Wait 100 ms.
  5. Assert the callback was **not** invoked.
- **Expected Results**: Work item is freed without callback execution. No resource leak.
- **Pass/Fail Criteria**: Callback not invoked; no leak.
- **Confidence**: [Low]
- **Source**: [PROPOSED]

---

### TC-WI-003: Work item allocation fails during shutdown [PROPOSED]

- **ID**: TC-WI-003
- **Title**: Work item allocation fails during shutdown
- **Linked Requirements**: REQ-WI-005
- **Test Level**: Unit
- **Preconditions**: Module initialized; rundown initiated
- **Steps**:
  1. Begin module termination (start rundown but do not complete teardown).
  2. Attempt `ebpf_epoch_allocate_work_item(context, callback)`.
  3. Verify return value is NULL.
- **Expected Results**: Allocation returns NULL because rundown protection cannot be acquired.
- **Pass/Fail Criteria**: Return value is NULL; no crash.
- **Confidence**: [Low]
- **Source**: [PROPOSED]

---

### TC-ROB-001: No use-after-free under reclamation hazard

- **ID**: TC-ROB-001
- **Title**: No use-after-free under reclamation hazard (epoch skew)
- **Linked Requirements**: REQ-ROB-002, REQ-COMP-002, REQ-MEM-006, REQ-WI-003
- **Test Level**: Integration
- **Preconditions**: `_test_helper` initialized; ≥ 4 CPUs
- **Steps**: See TC-COMP-002 (same test).
- **Expected Results**: No premature reclamation observed.
- **Pass/Fail Criteria**: `REQUIRE_FALSE(callback_while_reader_active)`.
- **Confidence**: [High]
- **Source**: `platform_unit_test.cpp:749` (`epoch_test_epoch_skew_reclamation_hazard`)

---

### TC-ROB-002: Spin reclamation stress test

- **ID**: TC-ROB-002
- **Title**: Spin reclamation stress test
- **Linked Requirements**: REQ-ROB-001, REQ-ROB-003, REQ-TS-002, REQ-WI-001, REQ-WI-002, REQ-WI-003
- **Test Level**: Stress
- **Preconditions**: `_test_helper` initialized; ≥ 2 CPUs
- **Steps**:
  1. **Reader thread** (CPU 0): Tight loop — enter epoch → read shared object's magic/generation fields 8× → exit epoch. Detect corruption via magic-field mismatch.
  2. **Writer thread** (CPU 1): Allocate new object (`VirtualAlloc`), atomically swap shared pointer, schedule old object's deletion as epoch work item. Callback marks page `PAGE_NOACCESS` then calls `VirtualFree`. Throttle at 256 outstanding work items / 4096 deferred frees.
  3. **Main thread**: Periodically calls `ebpf_epoch_synchronize()`.
  4. Run for configured duration (5 s – 600 s).
  5. Drain outstanding work items (10 s timeout).
  6. Assert `work_items_invoked >= work_items_scheduled`.
  7. Assert `thread_error == false`.
  8. Assert `callbacks_while_reader_active == 0`.
- **Expected Results**: Reader never observes freed memory (access violation would crash the process due to `PAGE_NOACCESS`). All scheduled work items eventually execute.
- **Pass/Fail Criteria**: `REQUIRE(work_items_invoked >= work_items_scheduled)`, `REQUIRE_FALSE(thread_error)`.
- **Confidence**: [High]
- **Source**: `platform_unit_test.cpp:994` (`epoch_test_spin_reclamation_stress`)

---

### TC-SYNC-001: Synchronize blocks until epoch completes [PROPOSED]

- **ID**: TC-SYNC-001
- **Title**: Synchronize blocks until epoch completes
- **Linked Requirements**: REQ-SYNC-001
- **Test Level**: Integration
- **Preconditions**: `_test_helper` initialized; ≥ 2 CPUs
- **Steps**:
  1. Thread A: Enter epoch → allocate → free → exit epoch.
  2. Main thread: Call `ebpf_epoch_synchronize()`.
  3. After synchronize returns, verify `ebpf_epoch_is_free_list_empty()` for the relevant CPU.
- **Expected Results**: `ebpf_epoch_synchronize` returns only after the epoch computation completes and free-list items are reclaimed.
- **Pass/Fail Criteria**: Free list is empty after synchronize.
- **Confidence**: [Medium] — synchronize is called in all existing tests but never explicitly checked against free-list state post-call.
- **Source**: [PROPOSED]

---

### TC-DIAG-001: Free-list empty query accuracy [PROPOSED]

- **ID**: TC-DIAG-001
- **Title**: Free-list empty query accuracy
- **Linked Requirements**: REQ-DIAG-001
- **Test Level**: Unit
- **Preconditions**: `_test_helper` initialized
- **Steps**:
  1. Verify `ebpf_epoch_is_free_list_empty(0)` returns `true` (no items).
  2. Enter epoch on CPU 0. Allocate and free memory.
  3. Exit epoch.
  4. Immediately check `ebpf_epoch_is_free_list_empty(0)` — may be `false` (item pending).
  5. Call `ebpf_epoch_synchronize()`.
  6. Verify `ebpf_epoch_is_free_list_empty(0)` returns `true`.
- **Expected Results**: Query correctly reflects free-list state before and after reclamation.
- **Pass/Fail Criteria**: Step 1 and 6 return `true`.
- **Confidence**: [Medium]
- **Source**: [PROPOSED] — `ebpf_epoch_is_free_list_empty` is used in TC-COMP-001 assertions but not tested for initial-empty or transition behavior.

---

## 6. Risk-Based Test Prioritization

| Risk | Impact | Likelihood | Priority | Related TCs |
|------|--------|------------|----------|-------------|
| Use-after-free of epoch-protected memory | **Critical** — data corruption, security vulnerability | Medium | **P0** | TC-ROB-001, TC-ROB-002 |
| Premature reclamation due to CPU epoch skew | **Critical** — silent data corruption | Medium | **P0** | TC-COMP-002, TC-ROB-001 |
| Deadlock or livelock during epoch computation | **High** — system hang | Low | **P1** | TC-COMP-001, TC-ROB-002 |
| Memory leak from un-drained free lists | **High** — resource exhaustion | Low | **P1** | TC-COMP-001, TC-LIFE-003 |
| Work item callback never invoked | **High** — deferred operations silently lost | Low | **P1** | TC-WI-001, TC-ROB-002 |
| Initialization failure leaks partial state | **Medium** — crash on retry | Low | **P2** | TC-LIFE-002 |
| Thread migration corrupts epoch state | **Medium** — incorrect reclamation timing | Low | **P2** | TC-ECS-003 |
| Cancel of un-scheduled work item leaks memory | **Low** — minor resource leak | Low | **P3** | TC-WI-002 |
| Free(NULL) crashes | **Low** — defensive coding issue | Very Low | **P3** | TC-MEM-004 |

---

## 7. Pass/Fail Criteria

### 7.1 Entry Criteria

- Platform and usersim layer compile and pass smoke tests.
- `ebpf_epoch_initiate()` returns `EBPF_SUCCESS` on the test machine.
- Machine has at least 2 logical CPUs (4 for full coverage of TC-COMP-002 / TC-ROB-001).

### 7.2 Exit Criteria

- All test cases with **[High]** confidence pass on all supported CPU configurations.
- All test cases tagged `[platform]` pass in CI (PR gate and scheduled runs).
- Stress test (TC-ROB-002) runs for the full configured duration without failure.
- No memory leaks detected by object tracking at `_test_helper` teardown.

### 7.3 Acceptance Thresholds

| Metric | Threshold |
|--------|-----------|
| Existing test pass rate | 100 % |
| Stress test: `work_items_invoked >= work_items_scheduled` | Must hold |
| Stress test: `callbacks_while_reader_active` | Must be 0 |
| Stale-items test: free lists empty within 100 ms | Must hold for 100/100 iterations |
| Epoch skew test: premature reclamation observed | Must be 0 in all 25 attempts |

---

## 8. Coverage Analysis

### 8.1 Existing Coverage

| API Function | Tested | Notes |
|-------------|--------|-------|
| `ebpf_epoch_initiate` | ✅ | Via `_test_helper` in every test |
| `ebpf_epoch_terminate` | ✅ | Via `_test_helper` destructor in every test |
| `ebpf_epoch_enter` | ✅ | Via `ebpf_epoch_scope_t` in every test |
| `ebpf_epoch_exit` | ✅ | Via `ebpf_epoch_scope_t` in every test |
| `ebpf_epoch_allocate` | ✅ | TC-MEM-001, TC-TS-001, TC-COMP-001 |
| `ebpf_epoch_allocate_with_tag` | ❌ | No test exercises this function directly |
| `ebpf_epoch_allocate_cache_aligned_with_tag` | ✅ | TC-MEM-003 |
| `ebpf_epoch_free` | ✅ | TC-MEM-001, TC-TS-001, TC-COMP-001 |
| `ebpf_epoch_free_cache_aligned` | ✅ | TC-MEM-003 |
| `ebpf_epoch_synchronize` | ✅ | Every test calls it |
| `ebpf_epoch_allocate_work_item` | ✅ | TC-COMP-002, TC-ROB-002 |
| `ebpf_epoch_schedule_work_item` | ✅ | TC-COMP-002, TC-ROB-002 |
| `ebpf_epoch_cancel_work_item` | ❌ | No test exercises cancellation |
| `ebpf_epoch_is_free_list_empty` | ✅ | TC-COMP-001 |

**Summary**: 11/13 public API functions are exercised by existing tests (85%).

### 8.2 Coverage Gaps

| Gap ID | Description | Risk | Proposed TC |
|--------|-------------|------|-------------|
| GAP-001 | `ebpf_epoch_allocate_with_tag` never tested directly | Low — same code path as `ebpf_epoch_allocate` but with tag parameter | TC-MEM-002 |
| GAP-002 | `ebpf_epoch_cancel_work_item` never tested | Medium — cancel path has its own assertions and cleanup logic | TC-WI-002 |
| GAP-003 | Initialization failure path not tested | Medium — error handling code in `ebpf_epoch_initiate` is dead code in tests | TC-LIFE-002 |
| GAP-004 | Rundown-protection rejection during shutdown not tested | Low — requires careful timing of shutdown sequence | TC-WI-003 |
| GAP-005 | `ebpf_epoch_free(NULL)` not tested | Low — defensive check per SAL annotation `_Frees_ptr_opt_` | TC-MEM-004 |
| GAP-006 | Thread migration (enter on CPU A, exit on CPU B) not tested | Medium — cross-CPU exit message path exercised only indirectly | TC-ECS-003 |
| GAP-007 | IRQL preservation across enter/exit not verified | Low — SAL annotation present but not runtime-checked | TC-ECS-002 |
| GAP-008 | `ebpf_epoch_synchronize` not tested for blocking semantics in isolation | Low — always called after exit, never verified it actually blocks | TC-SYNC-001 |
| GAP-009 | Terminate draining free-list items without prior synchronize not tested | Medium — rundown path code coverage | TC-LIFE-003 |
| GAP-010 | Free-list empty query not tested for transition from non-empty to empty | Low — tested only as assertion after polling | TC-DIAG-001 |

---

## 9. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-30 | Copilot (spec-extraction) | Initial extraction from codebase. Mapped 6 existing tests to 30+ requirements. Identified 10 coverage gaps with proposed test cases. |
