# Epoch Subsystem Requirements

## 1. Overview
- [KNOWN] The epoch subsystem provides read-side epoch tracking, deferred reclamation, and deferred callback execution for memory whose lifetime must extend past concurrent readers. Evidence: `libs\runtime\ebpf_epoch.h:40-136`, `docs\EpochBasedMemoryManagement.md:28-33`.
- [KNOWN] This draft is scoped to the runtime epoch implementation, its published API surface, its subsystem documentation, and the runtime/performance tests that exercise it. Evidence: `libs\runtime\ebpf_epoch.h:23-136`, `libs\runtime\ebpf_epoch.c:246-1067`, `libs\runtime\unit\platform_unit_test.cpp:634-1244`, `tests\performance\platform.cpp:8-69`.

## 2. Scope
- [KNOWN] In scope: `ebpf_epoch_initiate`, `ebpf_epoch_terminate`, `ebpf_epoch_enter`, `ebpf_epoch_exit`, epoch-managed allocation/free APIs, synchronization, epoch work items, and the free-list inspection helper. Evidence: `libs\runtime\ebpf_epoch.h:23-136`.
- [KNOWN] In scope: extension-facing epoch dispatch semantics documented for custom map providers. Evidence: `include\ebpf_extension.h:428-489`, `docs\CustomMaps.md:297-305`.
- [KNOWN] Out of scope: non-epoch consumers such as full map/object/program semantics except where they establish epoch integration constraints. Evidence: `libs\runtime\ebpf_object.c:217-257,348-355`, `libs\execution_context\ebpf_program.c:805-810,828-983`.

## 3. Definitions and Glossary
- [KNOWN] **Epoch-protected region**: a caller-bracketed interval between `ebpf_epoch_enter` and `ebpf_epoch_exit`. Evidence: `libs\runtime\ebpf_epoch.h:40-51`, `docs\EpochBasedMemoryManagement.md:61-79`.
- [KNOWN] **Free list**: a per-CPU queue of retired allocations, synchronization records, or work items waiting for reclamation. Evidence: `libs\runtime\ebpf_epoch.c:62-69,173-216,595-637`.
- [KNOWN] **Released epoch**: the newest epoch considered safe to reclaim on a CPU. Evidence: `libs\runtime\ebpf_epoch.c:64-66,853-868`, `docs\EpochBasedMemoryManagement.md:101-105,141-151`.
- [KNOWN] **Published epoch**: the global epoch value used to stamp active readers and retirements. Evidence: `libs\runtime\ebpf_epoch.c:8-25,791-800`, `docs\EpochBasedMemoryManagement.md:24-27,45-53`.
- [KNOWN] **Epoch work item**: a callback scheduled to run after the retired epoch becomes reclaimable. Evidence: `libs\runtime\ebpf_epoch.h:98-126`, `libs\runtime\ebpf_epoch.c:504-553,612-615,1056-1067`.

## 4. Requirements
- [KNOWN] **REQ-EPOCH-001**: The subsystem MUST initialize per-CPU epoch state and timed work queues before epoch APIs are used, and MUST tolerate repeated termination by returning immediately when the subsystem is not initialized.  
  **Confidence**: High.  
  **Evidence**: `libs\runtime\ebpf_epoch.h:23-37`, `libs\runtime\ebpf_epoch.c:246-311,313-350`.  
  **Acceptance criteria**:  
  - [INFERRED] AC-1: After successful initiation, each CPU has an initialized epoch-state list, free list, current epoch value, and work queue.  
  - [INFERRED] AC-2: `ebpf_epoch_terminate` on an uninitialized subsystem returns without dereferencing per-CPU state.

- [KNOWN] **REQ-EPOCH-002**: The subsystem MUST let callers mark an epoch-protected region by entering with caller-supplied `ebpf_epoch_state_t` storage, recording the current CPU and published epoch on entry, removing that state on exit, and supporting properly paired nested entry/exit calls.  
  **Confidence**: High.  
  **Evidence**: `libs\runtime\ebpf_epoch.h:40-51`, `libs\runtime\ebpf_epoch.c:357-423`, `docs\EpochBasedMemoryManagement.md:61-79`, `include\ebpf_extension.h:459-462`.  
  **Acceptance criteria**:  
  - [INFERRED] AC-1: Entry records a CPU identifier and epoch value into the supplied state object.  
  - [INFERRED] AC-2: Exit removes the same state from the owning CPU’s participant list before returning.
  - [KNOWN] AC-3: Nested entry/exit is valid when each entry uses paired state and exits in matching pairs. Evidence: `include\ebpf_extension.h:459-462`.

- [KNOWN] **REQ-EPOCH-003**: The subsystem MUST defer reclamation of epoch-managed allocations until the release epoch has advanced far enough that active readers cannot still observe the retired object.  
  **Confidence**: High.  
  **Evidence**: `libs\runtime\ebpf_epoch.h:54-90`, `libs\runtime\ebpf_epoch.c:468-501,595-637,782-868`, `docs\EpochBasedMemoryManagement.md:94-105,124-151`.  
  **Acceptance criteria**:  
  - [INFERRED] AC-1: `ebpf_epoch_free` and `ebpf_epoch_free_cache_aligned` retire objects onto a per-CPU free list instead of freeing them immediately.  
  - [INFERRED] AC-2: Reclamation occurs only when `freed_epoch <= released_epoch`.  
  - [KNOWN] AC-3: Regression and stress tests MUST observe no reclamation while a protected reader remains active. Evidence: `libs\runtime\unit\platform_unit_test.cpp:743-977,994-1244`.

- [KNOWN] **REQ-EPOCH-004**: The subsystem MUST offer a cache-aligned epoch allocation API whose returned pointer is cache-line aligned and whose reclamation path preserves that allocation strategy.  
  **Confidence**: High.  
  **Evidence**: `libs\runtime\ebpf_epoch.h:61-90`, `libs\runtime\ebpf_epoch.c:450-501,623-625`, `libs\runtime\unit\platform_unit_test.cpp:646-660`.  
  **Acceptance criteria**:  
  - [KNOWN] AC-1: Returned memory compares equal to `EBPF_CACHE_ALIGN_POINTER(memory)`. Evidence: `libs\runtime\unit\platform_unit_test.cpp:652-658`.  
  - [INFERRED] AC-2: Cache-aligned retirements are released through the cache-aligned free path.

- [KNOWN] **REQ-EPOCH-005**: The subsystem MUST provide a passive-level synchronization barrier that waits until work queued before the barrier becomes reclaimable.  
  **Confidence**: High.  
  **Evidence**: `libs\runtime\ebpf_epoch.h:93-96`, `libs\runtime\ebpf_epoch.c:555-575`, `docs\EpochBasedMemoryManagement.md:168-171`.  
  **Acceptance criteria**:  
  - [INFERRED] AC-1: `ebpf_epoch_synchronize` inserts a synchronization record into epoch retirement state and waits for its event to be signaled.  
  - [KNOWN] AC-2: Unit tests can use `ebpf_epoch_synchronize` to force reclamation progress after epoch exit. Evidence: `libs\runtime\unit\platform_unit_test.cpp:640-643,673-675,955-967,1196-1218`.

- [KNOWN] **REQ-EPOCH-006**: The subsystem MUST support deferred work items that can be allocated, either scheduled or canceled, invoked only after the item’s retirement becomes reclaimable, and treated as running outside any epoch unless the callback explicitly enters one.  
  **Confidence**: High.  
  **Evidence**: `libs\runtime\ebpf_epoch.h:98-126`, `libs\runtime\ebpf_epoch.c:504-553,612-615,1056-1067`, `docs\EpochBasedMemoryManagement.md:154-178`.  
  **Acceptance criteria**:  
  - [INFERRED] AC-1: Allocation acquires rundown protection and creates a preemptible work item.  
  - [INFERRED] AC-2: Scheduling retires the work item through the epoch free list.  
  - [INFERRED] AC-3: Cancellation frees the work item without invoking its callback.  
  - [KNOWN] AC-4: Scheduled callbacks do not run while a reader protected by a newer epoch remains active. Evidence: `libs\runtime\unit\platform_unit_test.cpp:824-839,949-977,1125-1244`.
  - [KNOWN] AC-5: Callbacks that need epoch-managed access enter/exit an epoch explicitly rather than relying on implicit callback protection. Evidence: `docs\EpochBasedMemoryManagement.md:173-178`.

- [KNOWN] **REQ-EPOCH-007**: The subsystem MUST handle the case where a caller exits an epoch on a different CPU than it entered by forwarding the removal to the owning CPU when the original entry occurred below `DISPATCH_LEVEL`.  
  **Confidence**: High.  
  **Evidence**: `libs\runtime\ebpf_epoch.c:383-411,897-916`, `docs\EpochBasedMemoryManagement.md:77-80`.  
  **Acceptance criteria**:  
  - [INFERRED] AC-1: A cross-CPU exit below `DISPATCH_LEVEL` sends an `EXIT_EPOCH` message to the CPU that owns the epoch-state entry.  
  - [INFERRED] AC-2: A cross-CPU exit from an entry that originated at `DISPATCH_LEVEL` fail-fasts instead of silently corrupting the per-CPU list.

- [KNOWN] **REQ-EPOCH-008**: The subsystem MUST expose epoch entry/exit and epoch-managed memory operations to extension map providers, and those operations MUST be used only within an epoch-protected region unless the runtime has already provided that protection.  
  **Confidence**: High.  
  **Evidence**: `include\ebpf_extension.h:428-489`, `docs\CustomMaps.md:297-305`.  
  **Acceptance criteria**:  
  - [KNOWN] AC-1: The map client dispatch table includes `epoch_enter`, `epoch_exit`, `epoch_allocate_with_tag`, `epoch_allocate_cache_aligned_with_tag`, `epoch_free`, and `epoch_free_cache_aligned`. Evidence: `include\ebpf_extension.h:479-489`.  
  - [KNOWN] AC-2: Provider dispatch and helper callbacks may call those APIs directly because they are already epoch-protected; other contexts must bracket them explicitly. Evidence: `include\ebpf_extension.h:459-477`, `docs\CustomMaps.md:302-305`.

- [KNOWN] **REQ-EPOCH-009**: The subsystem MUST provide a supported per-CPU diagnostic query that reports whether a CPU’s epoch free list is empty.  
  **Confidence**: High.  
  **Evidence**: `libs\runtime\ebpf_epoch.h:128-136`, `libs\runtime\ebpf_epoch.c:577-588,949-965`, `libs\runtime\unit\platform_unit_test.cpp:690-740`.
  **Acceptance criteria**:  
  - [KNOWN] AC-1: The query returns `true` only when the target CPU’s free list is empty. Evidence: `libs\runtime\ebpf_epoch.c:959-965`.  
  - [KNOWN] AC-2: The stale-item test can poll both CPUs until both free lists drain. Evidence: `libs\runtime\unit\platform_unit_test.cpp:732-739`.

## 5. Dependencies
- [KNOWN] **DEP-001**: The subsystem depends on platform CPU/IRQL primitives, kernel timer/DPC/event primitives, and cxplat memory/rundown/work-item services. Evidence: `libs\runtime\ebpf_epoch.c:253-303,521-524,565-574,734-759,1056-1067`.
- [KNOWN] **DEP-002**: The extension-facing contract depends on `ebpf_map_client_dispatch_table_t` and provider dispatch rules. Evidence: `include\ebpf_extension.h:455-489`, `docs\CustomMaps.md:297-305`.

## 6. Assumptions
- [KNOWN] **ASM-001**: Callers provide valid `ebpf_epoch_state_t` storage and pair each entry with a corresponding exit. Evidence: `libs\runtime\ebpf_epoch.h:40-51`, `include\ebpf_extension.h:459-462`.
- [KNOWN] **ASM-002**: Work item callbacks that need to touch epoch-managed structures explicitly enter and exit an epoch themselves. Evidence: `docs\EpochBasedMemoryManagement.md:173-178`.
- [KNOWN] **ASM-003**: Consumers of the supported diagnostic query call it against a valid CPU identifier. Evidence: `libs\runtime\ebpf_epoch.h:128-136`, `libs\runtime\ebpf_epoch.c:580-585`.

## 7. Risks
- [KNOWN] **RISK-001**: Mispaired enter/exit calls can leave stale participant records on per-CPU lists and delay or prevent reclamation. Evidence: `libs\runtime\ebpf_epoch.c:357-423,786-816`.
- [KNOWN] **RISK-002**: Calling extension-facing epoch memory APIs outside an epoch-protected region can lead to undefined behavior. Evidence: `include\ebpf_extension.h:469-477`.
- [KNOWN] **RISK-003**: Cross-CPU exit from an epoch entered at `DISPATCH_LEVEL` is treated as a fail-fast correctness violation. Evidence: `libs\runtime\ebpf_epoch.c:385-405`.
- [KNOWN] **RISK-004**: The cancellation path for epoch work items is specified and implemented but lacks subsystem-scoped validation in the current test set. Evidence: `libs\runtime\ebpf_epoch.c:540-553`; no matching epoch test in `libs\runtime\unit\platform_unit_test.cpp:634-1244`.

## 8. Revision History
- [KNOWN] Version 0.2 — 2026-06-30 — Reissued with repository-backed requirement evidence and self-contained traceability.
